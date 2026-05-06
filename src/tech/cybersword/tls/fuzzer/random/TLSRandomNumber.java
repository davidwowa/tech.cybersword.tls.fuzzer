package tech.cybersword.tls.fuzzer.random;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.util.Random;

public class TLSRandomNumber {
	public String generateASCIIString(int lenght) {
		Random random = new Random(255);
		StringBuilder string = new StringBuilder();

		for (int i = 0; i < lenght; i++) {
			string.append((char) random.nextInt(255));
		}
		return string.toString();
	}

	public long generateNumbers(long min, long max) {
		SecureRandom random = new SecureRandom();
		return random.nextLong(min, max + 1);
	}

	public BigDecimal generateBigDecimal(BigDecimal min, BigDecimal max) {
		SecureRandom random = new SecureRandom();
		BigDecimal range = max.subtract(min);
		BigDecimal randomNumberInRange = range.multiply(BigDecimal.valueOf(random.nextDouble()));
		return randomNumberInRange.add(min);
	}

	public static void main(String[] args) {
		testException();
	}

	public static void testException() {
		try {
			int a = 1;
			int b = 1;

			int c = a / b;

			throw new IllegalAccessError("test exceptiion");

			// System.out.println(c);
		} catch (NullPointerException e) {
			e.printStackTrace();
			System.out.println("other steps after this error");
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("other steps after other error");
		} finally {

		}

		System.out.println("next steps");
	}
}
