package com.dynatrace.hash4j.fuzz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.dynatrace.hash4j.fuzz.SimHashFuzz;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SimHashFuzzTest {
	@Test
	public void testEmpty() {
		FuzzedDataProvider provider = mock(FuzzedDataProvider.class);

		when(provider.consumeInt(anyInt(), anyInt())).thenReturn(1);
		when(provider.consumeLongs(anyInt())).thenReturn(new long[] {1});

		SimHashFuzz.fuzzerTestOneInput(provider);
	}
}
