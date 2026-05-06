package tech.cybersword.tls.fuzzer.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;

class LoggerUtilTest {

	@Test
	void writesLoggerFilesIntoLogDirectory() {
		Logger logger = LoggerUtil.getLogger("test.logger.directory");

		logger.info("logger directory test");

		assertTrue(Files.isDirectory(LoggerUtil.getLogDirectory()));
		assertTrue(logger.getHandlers().length >= 2);
	}
}
