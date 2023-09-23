package com.dynatrace.hash4j.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.dynatrace.hash4j.similarity.ElementHashProvider;
import com.dynatrace.hash4j.similarity.FastSimHashVersion;
import com.dynatrace.hash4j.similarity.MinHashVersion;
import com.dynatrace.hash4j.similarity.SimHashVersion;
import com.dynatrace.hash4j.similarity.SimilarityHashPolicy;
import com.dynatrace.hash4j.similarity.SimilarityHasher;
import com.dynatrace.hash4j.similarity.SimilarityHashing;
import com.dynatrace.hash4j.similarity.SuperMinHashVersion;


/**
 * This class provides a simple target for fuzzing SimHashers in the hash4j library.
 */
public class SimHashFuzz {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		int components = data.consumeInt(1, 100_000);	// allowing many more components would cause OOM
		int bits = data.consumeInt(1, 64);

		SimilarityHashPolicy policy;
		int hasher = data.consumeInt(0, 7);
		switch (hasher) {
			case 0:
				policy = SimilarityHashing.superMinHash(components, bits);
				break;
			case 1:
				policy = SimilarityHashing.superMinHash(components, bits,
						SuperMinHashVersion.values()[data.consumeInt(0, SuperMinHashVersion.values().length-1)]);
				break;
			case 2:
				policy = SimilarityHashing.minHash(components, bits);
				break;
			case 3:
				policy = SimilarityHashing.minHash(components, bits,
						MinHashVersion.values()[data.consumeInt(0, MinHashVersion.values().length-1)]);
				break;
			case 4:
				policy = SimilarityHashing.fastSimHash(components);
				break;
			case 5:
				policy = SimilarityHashing.fastSimHash(components,
						FastSimHashVersion.values()[data.consumeInt(0, FastSimHashVersion.values().length-1)]);
				break;
			case 6:
				policy = SimilarityHashing.simHash(components);
				break;
			case 7:
				policy = SimilarityHashing.simHash(components,
						SimHashVersion.values()[data.consumeInt(0, SimHashVersion.values().length-1)]);
				break;
			default:
				throw new IllegalStateException("Had unexpected switch-value: " + hasher);
		}

		SimilarityHasher simHasher = policy.createHasher();
		long[] hashes = data.consumeLongs(100);
		if (hashes.length > 0) {
			simHasher.compute(ElementHashProvider.ofValues(hashes));
		}
	}
}
