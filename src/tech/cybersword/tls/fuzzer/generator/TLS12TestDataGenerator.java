package tech.cybersword.tls.fuzzer.generator;

import java.util.Random;

import tech.cybersword.tls.fuzzer.util.StringUtil;

public class TLS12TestDataGenerator {

	private static TLS12TestDataGenerator instance;

	private TLS12TestDataGenerator() {
	}

	public static TLS12TestDataGenerator getInstance() {
		if (null == instance) {
			instance = new TLS12TestDataGenerator();
		}
		return instance;
	}

	public byte[] generateExampleTLSHello() {
		return TLSProtocolDataGenerator.getInstance().createTLS12ClientHello();
	}

	public byte[] generateExampleTLSHelloRandomExtensionData() {
		return TLSProtocolDataGenerator.getInstance().createTLS12ClientHelloWithRandomExtensions();
	}

	public byte[] createTestTLSHello() {
		String exampleTLSHello = "16 02 01 00 a5 01 00 00 a1 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 01 00 00 58 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00 0d 00 12 00 10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02 03 ff 01 00 01 00 00 12 00 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(exampleTLSHello);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestTLSHelloWithRandomOption() {
		Random random = new Random();
		int r = random.nextInt(17);

		String rr = "" + r;

		if (r < 10) {
			rr = 0 + rr;
		}

		String exampleTLSHello = rr
				+ " 02 01 00 a5 01 00 00 a1 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 01 00 00 58 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00 0d 00 12 00 10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02 03 ff 01 00 01 00 00 12 00 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(exampleTLSHello);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestRecordHeader0() {
		String str = "16 03 01 00 a5";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestHandshakeHeader1() {
		String str = "01 00 00 a1";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestClientVersion2() {
		String str = "03 03";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestClientRandom3() {
		String str = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestSessionID4() {
		String str = "00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestCipherSuites5() {
		String str = "00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14 c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestCompressionMethods6() {
		String str = "01 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}
}
