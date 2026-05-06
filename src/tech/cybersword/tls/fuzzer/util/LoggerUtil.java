package tech.cybersword.tls.fuzzer.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LoggerUtil {

	private static final Path LOG_DIRECTORY = Path.of("log");

    public static Logger getLogger(String className) {

        Date date = new Date();

        Logger logger = Logger.getLogger(className);
        logger.setUseParentHandlers(false);
        if (logger.getHandlers().length > 0) {
            return logger;
        }
        Handler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);
        consoleHandler.setFormatter(new SimpleFormatter());

        logger.addHandler(consoleHandler);
        try {
            Files.createDirectories(LOG_DIRECTORY);
            String logFilePattern = LOG_DIRECTORY.resolve(className + ".TLSFuzzer_" + sanitize(date.toString())
                    + ".log").toString();
            FileHandler fileHandler = new FileHandler(logFilePattern, 1024 * 1024, 5, true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
        } catch (IOException | SecurityException e) {
            logger.log(Level.SEVERE, "Error occurred in setting up the logger", e);
            e.printStackTrace();
        }

        logger.setLevel(Level.ALL);

        return logger;
    }

	public static Path getLogDirectory() {
		return LOG_DIRECTORY;
	}

	private static String sanitize(String value) {
		return value.replaceAll("[^A-Za-z0-9._-]", "_");
	}
}
