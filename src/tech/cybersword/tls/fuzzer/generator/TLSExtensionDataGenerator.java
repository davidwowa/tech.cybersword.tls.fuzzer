package tech.cybersword.tls.fuzzer.generator;

import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.util.LoggerUtil;
import tech.cybersword.tls.fuzzer.util.RandomUtil;
import tech.cybersword.tls.fuzzer.util.StringUtil;

public class TLSExtensionDataGenerator {

	private static final Logger logger = LoggerUtil.getLogger(TLSExtensionDataGenerator.class.getName());

	public byte[] createTestExtensionLength7() {
		String str = "00 a3";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionLength\t\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionServerName8() {
		// 65 - 74 -> example.ulfheim.net
		String str = "00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionServerName\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionECPointsFormats9() {
		String str = "00 0b 00 04 03 00 01 02";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionECPointsFormats\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSupportedGroups10() {
		String str = "00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSupportedGroups\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSessionTicket11() {
		String str = "00 23 00 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSessionTicket\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionEncryptThenMAC12() {
		String str = "00 16 00 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionEncryptThenMAC\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionExtendedMasterSecret13() {
		String str = "00 17 00 00";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionExtendedMasterSecret\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSignatureAlgorithms14() {
		String str = "00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSignatureAlgorithms\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSupportedVersions15() {
		String str = "00 2b 00 03 02 03 04";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSupportedVersions\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionPSKKeyExchangeModes16() {
		String str = "00 2d 00 02 01 01";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tPSKKeyExchangeModes\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionKeyShare17() {
		String str = "00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54";
		String tmp = StringUtil.getInstance().removeWhiteCharacters(str);
		byte[] array = StringUtil.getInstance().convertFrom(tmp);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionKeyShare\t\t\t%s", array.length));
		}
		return array;
	}

	// randoms same size

	public byte[] createTestExtensionServerNameR8() {
		// 65 - 74 -> example.ulfheim.net
		// 2^14 is max value for server name
		byte[] array = RandomUtil.getInstance()
				.generateRandomArray(RandomUtil.getInstance().generateRandomNumber(1 << 13, 1 << 14));
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionServerName\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionECPointsFormatsR9() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(8);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionECPointsFormats\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSupportedGroupsR10() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(26);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSupportedGroups\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSessionTicketR11() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(4);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSessionTicket\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionEncryptThenMACR12() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(4);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionEncryptThenMAC\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionExtendedMasterSecretR13() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(4);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionExtendedMasterSecret\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSignatureAlgorithmsR14() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(34);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSignatureAlgorithms\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionSupportedVersionsR15() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(7);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionSupportedVersions\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionPSKKeyExchangeModesR16() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(6);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tPSKKeyExchangeModes\t\t\t%s", array.length));
		}
		return array;
	}

	public byte[] createTestExtensionKeyShareR17() {
		byte[] array = RandomUtil.getInstance().generateRandomArray(42);
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(String.format("length\tExtensionKeyShare\t\t\t%s", array.length));
		}
		return array;
	}
}
