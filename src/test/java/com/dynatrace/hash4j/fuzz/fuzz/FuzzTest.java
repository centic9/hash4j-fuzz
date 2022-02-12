package com.dynatrace.hash4j.fuzz.fuzz;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.dynatrace.hash4j.fuzz.Fuzz;

class FuzzTest {
	@Test
	public void testEmpty() {
		Fuzz.fuzzerTestOneInput(new byte[] {});
		Fuzz.fuzzerTestOneInput(new byte[] { ' '});
	}

	@Test
	public void testLine() {
		Fuzz.fuzzerTestOneInput("some text".getBytes(StandardCharsets.UTF_8));
	}

	@Test
	public void testFile() throws IOException {
		Fuzz.fuzzerTestOneInput(FileUtils.readFileToByteArray(new File("src/test/resources/samples.txt")));
	}

	@Disabled("Local test for verifying a slow run")
	@Test
	public void testSlowUnit() {
		//Fuzz.fuzzerTestOneInput(FileUtils.readFileToByteArray(new File("slow-unit-0a0b0ce97bb332cd9f8fde03e03840768a81d29d")));
	}
}
