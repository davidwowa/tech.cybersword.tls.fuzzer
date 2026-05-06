package tech.cybersword.tls.fuzzer.generator;

import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.util.ArrayUtils;
import tech.cybersword.tls.fuzzer.util.LoggerUtil;
import tech.cybersword.tls.fuzzer.util.RandomUtil;
import tech.cybersword.tls.fuzzer.util.StringUtil;

public class TLS13TestDataGenerator {

	private static final Logger logger = LoggerUtil.getLogger(TLS13TestDataGenerator.class.getName());

	private static TLS13TestDataGenerator instance;

	private TLS13TestDataGenerator() {
	}

	public static TLS13TestDataGenerator getInstance() {
		if (null == instance) {
			instance = new TLS13TestDataGenerator();
		}
		return instance;
	}

	public byte[] generateExampleTLSHello() {
		var arr = TLSProtocolDataGenerator.getInstance().createTLS13ClientHello();
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(StringUtil.getInstance().toHexString(arr));
		}
		return arr;
	}

	public byte[] generateExampleTLSHelloRandomExtensionData() {
		var arr = TLSProtocolDataGenerator.getInstance().createTLS13ClientHelloWithRandomExtensions();
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(StringUtil.getInstance().toHexString(arr));
		}
		return arr;
	}

	public byte[] generateExampleTLSRHelloRandomExtensionData() {
		var recordHeader = createTLSRecordHeader0();
		var handshakeHeader = createTestHandshakeHeader1(RandomUtil.getInstance().generateRandomNumber(1, 256));
		var clientVersion = createTestClientVersion2(RandomUtil.getInstance().generateRandomNumber(1, 256));
		var clientRandom = createTestClientRandom3(RandomUtil.getInstance().generateRandomNumber(1, 256));
		var sessionID = createTestSessionID4(RandomUtil.getInstance().generateRandomNumber(1, 256));
		var cipherSuite = createTestCipherSuites5(RandomUtil.getInstance().generateRandomNumber(1, 256));
		var compressionMethods = createTestCompressionMethods6(RandomUtil.getInstance().generateRandomNumber(1, 256));

		ArrayUtils arrayUtils = new ArrayUtils();

		TLSExtensionDataGenerator extensionDataGenerator = new TLSExtensionDataGenerator();

		var arr = arrayUtils.appendAllArrays(recordHeader, handshakeHeader, clientVersion, clientRandom, sessionID,
				cipherSuite, compressionMethods, extensionDataGenerator.createTestExtensionLength7(),
				extensionDataGenerator.createTestExtensionServerNameR8(),
				extensionDataGenerator.createTestExtensionECPointsFormatsR9(),
				extensionDataGenerator.createTestExtensionSupportedGroupsR10(),
				extensionDataGenerator.createTestExtensionSessionTicketR11(),
				extensionDataGenerator.createTestExtensionEncryptThenMACR12(),
				extensionDataGenerator.createTestExtensionExtendedMasterSecretR13(),
				extensionDataGenerator.createTestExtensionSignatureAlgorithmsR14(),
				extensionDataGenerator.createTestExtensionSupportedVersionsR15(),
				extensionDataGenerator.createTestExtensionPSKKeyExchangeModesR16(),
				extensionDataGenerator.createTestExtensionKeyShareR17());

		if (logger.isLoggable(Level.FINE)) {
			logger.fine(StringUtil.getInstance().toHexString(arr));
		}
		return arr;
	}

	public byte[] createTestTLSHello() {
		String exampleTLSHello = "16 03 01 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(exampleTLSHello);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTLSRecordHeader0() {
		String str = "16 03 01 00 f8";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestHandshakeHeader1() {
		String str = "01 00 00 f4";
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
		String str = "20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestCipherSuites5() {
		String str = "00 08 13 02 13 03 13 01 00 ff";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	public byte[] createTestCompressionMethods6() {
		String str = "01 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		return StringUtil.getInstance().convertFrom(tmp);
	}

	// random
	public byte[] createTLSRecordHeader0(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestHandshakeHeader1(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestClientVersion2(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestClientRandom3(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestSessionID4(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestCipherSuites5(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}

	public byte[] createTestCompressionMethods6(int length) {
		return RandomUtil.getInstance().generateRandomArray(length);
	}
}
