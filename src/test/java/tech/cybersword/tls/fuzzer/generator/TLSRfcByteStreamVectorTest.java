package tech.cybersword.tls.fuzzer.generator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class TLSRfcByteStreamVectorTest {

	@Test
	void createsBroadRfcVectorCatalog() {
		List<TLSFuzzVector> vectors = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors();

		assertTrue(vectors.size() >= 48000);
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("all-record-header-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("all-handshake-header-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("all-alert-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("xargs-tls12-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("xargs-tls13-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("rfc5246-handshake-type-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("rfc8446-handshake-type-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("rfc-alert-fatal-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("rfc-extension-type-")));
		assertTrue(vectors.stream().anyMatch(vector -> vector.getName().startsWith("malformed-")));
	}

	@Test
	void splitsRfcVectorCatalogIntoDashboardCategories() {
		List<TLSFuzzVector> vectors = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors();
		Map<String, List<TLSFuzzVector>> categories = TLSProtocolDataGenerator.getInstance()
				.createRfcByteStreamVectorsByCategory();

		int categorizedCount = categories.values().stream().mapToInt(List::size).sum();

		assertEquals(vectors.size(), categorizedCount);
		assertEquals(14, categories.size());
		assertTrue(categories.containsKey("client-hello"));
		assertTrue(categories.containsKey("record-header"));
		assertTrue(categories.containsKey("handshake-header"));
		assertTrue(categories.containsKey("alert-header"));
		assertTrue(categories.containsKey("extension-type"));
		assertTrue(categories.values().stream().flatMap(List::stream).allMatch(vector -> !vector.getCategory().isBlank()));
	}

	@Test
	void vectorNamesAreUnique() {
		List<TLSFuzzVector> vectors = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors();
		Set<String> names = new HashSet<>();

		for (TLSFuzzVector vector : vectors) {
			assertTrue(names.add(vector.getName()), "duplicate vector name " + vector.getName());
		}
	}

	@Test
	void wellFormedRecordVectorsHaveConsistentRecordLengths() {
		List<TLSFuzzVector> vectors = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors();

		for (TLSFuzzVector vector : vectors) {
			if (vector.getName().startsWith("malformed-") || vector.getName().startsWith("all-record-header-")) {
				continue;
			}
			byte[] data = vector.getData();
			assertTrue(data.length >= 5, vector.getName());
			assertEquals(data.length - 5, uint16(data, 3), vector.getName());
		}
	}

	@Test
	void vectorDataIsDefensivelyCopied() {
		TLSFuzzVector vector = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors().get(0);
		byte[] firstCopy = vector.getData();
		byte original = firstCopy[0];

		firstCopy[0] = (byte) 0xff;

		assertEquals(original, vector.getData()[0]);
		assertFalse(firstCopy[0] == vector.getData()[0]);
	}

	private int uint16(byte[] data, int offset) {
		return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
	}
}
