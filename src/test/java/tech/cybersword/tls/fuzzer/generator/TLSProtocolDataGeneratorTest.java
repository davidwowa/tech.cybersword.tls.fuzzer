package tech.cybersword.tls.fuzzer.generator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TLSProtocolDataGeneratorTest {

	@Test
	void createsLengthConsistentTLS12ClientHello() {
		byte[] clientHello = TLSProtocolDataGenerator.getInstance().createTLS12ClientHello();

		assertRecordAndHandshakeLengths(clientHello);
		assertArrayEquals(new byte[] { 0x16, 0x03, 0x01 }, new byte[] { clientHello[0], clientHello[1], clientHello[2] });
		assertEquals(0x01, clientHello[5] & 0xff);
		assertArrayEquals(new byte[] { 0x03, 0x03 }, new byte[] { clientHello[9], clientHello[10] });
		assertTrue(containsExtension(clientHello, 0x0000));
		assertTrue(containsExtension(clientHello, 0x0017));
	}

	@Test
	void createsLengthConsistentTLS13ClientHello() {
		byte[] clientHello = TLSProtocolDataGenerator.getInstance().createTLS13ClientHello();

		assertRecordAndHandshakeLengths(clientHello);
		assertTrue(containsExtension(clientHello, 0x002b));
		assertTrue(containsExtension(clientHello, 0x002d));
		assertTrue(containsExtension(clientHello, 0x0033));
	}

	@Test
	void createsLengthConsistentRandomExtensionClientHello() {
		byte[] clientHello = TLSProtocolDataGenerator.getInstance().createTLS13ClientHelloWithRandomExtensions();

		assertRecordAndHandshakeLengths(clientHello);
		assertTrue(containsExtension(clientHello, 0x0033));
	}

	private void assertRecordAndHandshakeLengths(byte[] record) {
		int recordLength = uint16(record, 3);
		int handshakeLength = uint24(record, 6);

		assertEquals(record.length - 5, recordLength);
		assertEquals(record.length - 9, handshakeLength);
	}

	private boolean containsExtension(byte[] record, int expectedType) {
		int cursor = 9;
		cursor += 2;
		cursor += 32;
		cursor += 1 + (record[cursor] & 0xff);
		cursor += 2 + uint16(record, cursor);
		cursor += 1 + (record[cursor] & 0xff);

		int extensionsEnd = cursor + 2 + uint16(record, cursor);
		cursor += 2;
		while (cursor + 4 <= extensionsEnd) {
			int type = uint16(record, cursor);
			int length = uint16(record, cursor + 2);
			if (type == expectedType) {
				return true;
			}
			cursor += 4 + length;
		}
		return false;
	}

	private int uint16(byte[] data, int offset) {
		return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
	}

	private int uint24(byte[] data, int offset) {
		return ((data[offset] & 0xff) << 16) | ((data[offset + 1] & 0xff) << 8) | (data[offset + 2] & 0xff);
	}
}
