package tech.cybersword.tls.fuzzer.util;

import java.security.SecureRandom;

public class RandomUtil {

	private static final SecureRandom random = new SecureRandom();

	public static RandomUtil instance;

	private RandomUtil() {
	}

	public static RandomUtil getInstance() {
		if (null == instance) {
			instance = new RandomUtil();
		}
		return instance;
	}

	public byte[] generateRandomArray(int arrayLength) {
		byte[] arr = new byte[arrayLength];
		random.nextBytes(arr);
		return arr;
	}

	public byte[] getEmptyArray() {
		return new byte[0];
	}

	public int generateRandomNumber(int start, int end) {
		if (start >= end) {
			return start;
		}
		return random.nextInt(start, end);
	}
}
