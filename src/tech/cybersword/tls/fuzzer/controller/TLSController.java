package tech.cybersword.tls.fuzzer.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.client.TLSClient;
import tech.cybersword.tls.fuzzer.common.CommonProperties;
import tech.cybersword.tls.fuzzer.dashboard.BrowserDashboardServer;
import tech.cybersword.tls.fuzzer.dashboard.FuzzerStatusRegistry;
import tech.cybersword.tls.fuzzer.dashboard.TLSReportCreator;
import tech.cybersword.tls.fuzzer.dashboard.TLSHandshakeFlows;
import tech.cybersword.tls.fuzzer.dashboard.TLSHandshakeStep;
import tech.cybersword.tls.fuzzer.generator.TLSFuzzVector;
import tech.cybersword.tls.fuzzer.generator.TLSProtocolDataGenerator;
import tech.cybersword.tls.fuzzer.generator.TLS12TestDataGenerator;
import tech.cybersword.tls.fuzzer.generator.TLS13TestDataGenerator;
import tech.cybersword.tls.fuzzer.ui.TLSDashboard;
import tech.cybersword.tls.fuzzer.ui.TLSSystemTray;
import tech.cybersword.tls.fuzzer.util.LoggerUtil;
import tech.cybersword.tls.fuzzer.util.RandomUtil;
import tech.cybersword.tls.fuzzer.util.StringUtil;

public class TLSController {

	public enum TestSuite {
		ALL,
		TLS12,
		TLS13,
		RFC,
		RANDOM
	}

	private static final Logger logger = LoggerUtil.getLogger(TLSController.class.getName());

	public static String tlsHost = CommonProperties.getInstance().getTlsHost();
	public static int tlsPort = CommonProperties.getInstance().getTlsPort();
	public static int amountTLSRequests = CommonProperties.getInstance().getAmountTLSRequests();
	public static int threadsAmount = CommonProperties.getInstance().getThreadsAmount();

	private static TLSController instance;
	private ExecutorService runExecutor;
	private List<Future<?>> runFutures = List.of();
	private volatile boolean stopRequested;
	private volatile boolean running;
	private volatile TestSuite activeSuite = TestSuite.ALL;
	private volatile long runStartedAt;

	private TLSController() {
		TLSSystemTray.getInstance();
	}

	public static TLSController getInstance() {
		if (instance == null) {
			instance = new TLSController();
		}
		return instance;
	}

	public static void main(String[] args) {
		TLSController.getInstance().mainTest();
	}

	public void mainTest() {
		BrowserDashboardServer.getInstance().start();
		TLSDashboard.getInstance().show();
		FuzzerStatusRegistry.getInstance().addLog("dashboard ready; select a test suite to start");
		if (logger.isLoggable(Level.INFO)) {
			logger.info("TLS fuzzer dashboard ready; waiting for start button");
		}
	}

	public synchronized boolean startTests(String host, int port, TestSuite suite) {
		if (running) {
			FuzzerStatusRegistry.getInstance().addLog("start ignored, test already running");
			return false;
		}
		tlsHost = host;
		tlsPort = port;
		activeSuite = suite;
		stopRequested = false;
		running = true;
		runStartedAt = System.currentTimeMillis();
		TLSClient client = TLSClient.getInstance();
		FuzzerStatusRegistry.getInstance().clear();

		runExecutor = Executors.newFixedThreadPool(threadsAmount);

		if (logger.isLoggable(Level.INFO)) {
			logger.info(String.format("start tls fuzzy test suite %s host %s, port %s, amount tls requests %s", suite,
					tlsHost, tlsPort, amountTLSRequests));
		}
		FuzzerStatusRegistry.getInstance()
				.addLog(String.format("suite=%s target=%s:%s started", suite, tlsHost, tlsPort));

		List<Future<?>> futures = new ArrayList<>();
		if (suite == TestSuite.ALL || suite == TestSuite.RANDOM) {
			futures.add(simpleTLSRandomFixArray(client, runExecutor));
			futures.add(simpleTLSRandomArray(client, runExecutor));
		}
		if (suite == TestSuite.ALL || suite == TestSuite.TLS12) {
			futures.add(simpleTLS12HelloTest(client, runExecutor));
			futures.add(simpleTLS12HelloRandomExtensionTest(client, runExecutor));
		}
		if (suite == TestSuite.ALL || suite == TestSuite.TLS13) {
			futures.add(simpleTLS13HelloTest(client, runExecutor));
			futures.add(simpleTLS13HelloRandomExtensionTest(client, runExecutor));
			futures.add(simpleTLS13RHelloRandomExtensionTest(client, runExecutor));
		}
		if (suite == TestSuite.ALL || suite == TestSuite.RFC) {
			futures.addAll(rfcByteStreamSuites(client, runExecutor));
		}
		runFutures = List.copyOf(futures);
		runExecutor.shutdown();
		Thread monitor = new Thread(() -> waitForFuzzerJobs(runFutures, runExecutor), "tls-fuzzer-monitor");
		monitor.setDaemon(false);
		monitor.start();
		return true;
	}

	public synchronized void stopTests() {
		stopRequested = true;
		for (Future<?> future : runFutures) {
			future.cancel(true);
		}
		if (runExecutor != null) {
			runExecutor.shutdownNow();
		}
		running = false;
		FuzzerStatusRegistry.getInstance().addLog("stop requested");
	}

	public boolean isStopRequested() {
		return stopRequested;
	}

	public boolean isRunning() {
		return running;
	}

	public TestSuite getActiveSuite() {
		return activeSuite;
	}

	public String getTargetHost() {
		return tlsHost;
	}

	public int getTargetPort() {
		return tlsPort;
	}

	public long getRunStartedAt() {
		return runStartedAt;
	}

	private static List<Future<?>> rfcByteStreamSuites(TLSClient client, ExecutorService executor) {
		Map<String, List<TLSFuzzVector>> categorizedVectors = TLSProtocolDataGenerator.getInstance()
				.createRfcByteStreamVectorsByCategory();
		List<Future<?>> futures = new ArrayList<>();
		for (Map.Entry<String, List<TLSFuzzVector>> entry : categorizedVectors.entrySet()) {
			futures.add(rfcByteStreamSuite(client, executor, entry.getKey(), entry.getValue()));
		}
		return futures;
	}

	private static Future<?> rfcByteStreamSuite(TLSClient client, ExecutorService executor, String category,
			List<TLSFuzzVector> vectors) {
		String jobName = "rfcByteStreamSuite:" + category;
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, vectors.size());
			for (int i = 0; i < vectors.size() && !TLSController.getInstance().isStopRequested(); i++) {
				TLSFuzzVector vector = vectors.get(i);
				try {
						byte[] response = sendAndRecord(client, jobName, null, i + 1, vector.getData(), vector.getName());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(vector.getName() + " response " + StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, vectors.size(), i + 1, lastStatus, vector.getName());
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE, String.format("%s: error on vector %s", jobName, vector.getName()), e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("%s: end after %s ms", jobName, System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLSRandomFixArray(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLSRandomFixArray";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = RandomUtil.getInstance()
								.generateRandomArray(CommonProperties.getInstance().getRandomArraySize());
						byte[] response = sendAndRecord(client, jobName, null, i + 1, payload, "fixed random payload");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE,
									String.format("simpleTLSRandomFixArray: error tls fuzzer test number %s", i), e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(
					String.format("simpleTLSRandomFixArray: end after %s ms", System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLSRandomArray(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLSRandomArray";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
					int randomNumber = RandomUtil.getInstance().generateRandomNumber(
							CommonProperties.getInstance().getRandomMinArraySize(),
							CommonProperties.getInstance().getRandomMaxArraySize());
						byte[] payload = RandomUtil.getInstance().generateRandomArray(randomNumber);
						byte[] response = sendAndRecord(client, jobName, null, i + 1, payload, "variable random payload");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE, String.format("simpleTLSRandomArray: error tls fuzzer test number %s", i),
									e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLSRandomArray: end after %s ms", System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLS12HelloTest(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLS12HelloTest";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = TLS12TestDataGenerator.getInstance().generateExampleTLSHello();
						byte[] response = sendAndRecord(client, jobName, TLSHandshakeFlows.tls12ClientHello(), i + 1, payload,
								"TLS 1.2 ClientHello");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE, String.format("simpleTLS12HelloTest: error tls fuzzer test number %s", i),
									e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLS12HelloTest: end after %s ms", System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLS12HelloRandomExtensionTest(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLS12HelloRandomExtensionTest";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = TLS12TestDataGenerator.getInstance().generateExampleTLSHelloRandomExtensionData();
						byte[] response = sendAndRecord(client, jobName, TLSHandshakeFlows.tls12ClientHello(), i + 1, payload,
								"TLS 1.2 ClientHello with random extension data");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE, String.format(
									"simpleTLS12HelloRandomExtensionTest: error tls fuzzer test number %s", i), e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLS12HelloRandomExtensionTest: end after %s ms",
					System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLS13HelloTest(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLS13HelloTest";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = TLS13TestDataGenerator.getInstance().generateExampleTLSHello();
						byte[] response = sendAndRecord(client, jobName, TLSHandshakeFlows.tls13ClientHello(), i + 1, payload,
								"TLS 1.3 ClientHello");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE, String.format("simpleTLS13HelloTest: error tls fuzzer test number %s", i),
									e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLS13HelloTest: end after %s ms",
					System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLS13HelloRandomExtensionTest(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLS13HelloRandomExtensionTest";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = TLS13TestDataGenerator.getInstance().generateExampleTLSHelloRandomExtensionData();
						byte[] response = sendAndRecord(client, jobName, TLSHandshakeFlows.tls13ClientHello(), i + 1, payload,
								"TLS 1.3 ClientHello with random extension data");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE,
									String.format("simpleTLS13HelloRandomExtensionTest: error tls fuzzer test number %s", i),
									e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLS13HelloRandomExtensionTest: end after %s ms",
					System.currentTimeMillis() - startTime));
		});
	}

	private static Future<?> simpleTLS13RHelloRandomExtensionTest(TLSClient client, ExecutorService executor) {
		String jobName = "simpleTLS13RHelloRandomExtensionTest";
		AtomicInteger lastStatus = new AtomicInteger(-1);
		return executor.submit(() -> {
			long startTime = System.currentTimeMillis();
			FuzzerStatusRegistry.getInstance().start(jobName, amountTLSRequests);
			for (int i = 0; i < amountTLSRequests && !TLSController.getInstance().isStopRequested(); i++) {
				try {
						byte[] payload = TLS13TestDataGenerator.getInstance().generateExampleTLSRHelloRandomExtensionData();
						byte[] response = sendAndRecord(client, jobName, TLSHandshakeFlows.tls13ClientHello(), i + 1, payload,
								"TLS 1.3 randomized ClientHello variant");
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					} catch (Exception e) {
						if (logger.isLoggable(Level.SEVERE)) {
							logger.log(Level.SEVERE,
									String.format("simpleTLS13RHelloRandomExtensionTest: error tls fuzzer test number %s", i),
									e);
						}
						FuzzerStatusRegistry.getInstance().failed(jobName, e);
					}
			}
			FuzzerStatusRegistry.getInstance().success(jobName);
			logger.info(String.format("simpleTLS13RHelloRandomExtensionTest: end after %s ms",
					System.currentTimeMillis() - startTime));
		});
	}

	private static void waitForFuzzerJobs(List<Future<?>> futures, ExecutorService executor) {
		for (Future<?> future : futures) {
			try {
				future.get();
			} catch (Exception e) {
				if (logger.isLoggable(Level.SEVERE)) {
					logger.log(Level.SEVERE, "TLS fuzzer job failed", e);
				}
			}
		}
		try {
			if (!executor.awaitTermination(1, TimeUnit.MINUTES) && logger.isLoggable(Level.WARNING)) {
				logger.warning("TLS fuzzer executor did not terminate within timeout");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		TLSController controller = TLSController.getInstance();
		controller.running = false;
		controller.stopRequested = false;
		try {
			TLSReportCreator.getInstance().createReport(controller.getTargetHost(), controller.getTargetPort(),
					controller.getActiveSuite(), controller.getRunStartedAt(), System.currentTimeMillis(),
					FuzzerStatusRegistry.getInstance().snapshot(), FuzzerStatusRegistry.getInstance().logSnapshot());
		} catch (Exception e) {
			if (logger.isLoggable(Level.SEVERE)) {
				logger.log(Level.SEVERE, "Could not create TLS fuzzer PDF report", e);
			}
			FuzzerStatusRegistry.getInstance().addLog("pdf report failed: " + e.getMessage());
		}
		FuzzerStatusRegistry.getInstance().addLog("test run ended; browser dashboard remains active");
	}

	private static byte[] sendAndRecord(TLSClient client, String jobName, TLSHandshakeStep step, int iteration,
			byte[] payload, String label) {
		String requestHex = StringUtil.getInstance().toHexString(payload);
		String payloadLog = String.format("Request Payload job=%s iteration=%s label=%s bytes=%s hex=%s", jobName,
				iteration, label, payload.length, requestHex);
		FuzzerStatusRegistry.getInstance().addLog(payloadLog);
		if (logger.isLoggable(Level.INFO)) {
			logger.info(payloadLog);
		}
		if (step != null) {
			FuzzerStatusRegistry.getInstance().recordHandshakeStep(step, "TESTING", jobName, iteration, payload.length, 0,
					"request generated");
		}
		byte[] response = client.sendTLSMessage(tlsHost, tlsPort, payload);
		String responseHex = StringUtil.getInstance().toHexString(response);
		String responseSummary = classifyResponse(response);
		String responseLog = String.format(
				"Server Response job=%s iteration=%s label=%s bytes=%s classification=%s hex=%s", jobName, iteration,
				label, response.length, responseSummary, responseHex);
		FuzzerStatusRegistry.getInstance().addLog(responseLog);
		if (logger.isLoggable(Level.INFO)) {
			logger.info(responseLog);
		}
		if (step != null) {
			FuzzerStatusRegistry.getInstance().recordHandshakeStep(step, "OBSERVED", jobName, iteration, payload.length,
					response.length, responseSummary);
		}
		return response;
	}

	private static String classifyResponse(byte[] response) {
		if (response.length == 0) {
			return "NO_RESPONSE";
		}
		if (response.length < 5) {
			return "MALFORMED_TLS_RECORD bytes=" + response.length;
		}
		int contentType = response[0] & 0xff;
		int recordLength = ((response[3] & 0xff) << 8) | (response[4] & 0xff);
		if (recordLength + 5 > response.length) {
			return "TRUNCATED_TLS_RECORD declared=" + recordLength + " bytes=" + response.length;
		}
		return switch (contentType) {
		case 20 -> "CHANGE_CIPHER_SPEC bytes=" + response.length;
		case 21 -> classifyAlert(response);
		case 22 -> "HANDSHAKE_RECORD bytes=" + response.length;
		case 23 -> "APPLICATION_DATA bytes=" + response.length;
		default -> "UNKNOWN_TLS_RECORD type=" + contentType + " bytes=" + response.length;
		};
	}

	private static String classifyAlert(byte[] response) {
		if (response.length < 7) {
			return "TLS_ALERT malformed bytes=" + response.length;
		}
		int level = response[5] & 0xff;
		int description = response[6] & 0xff;
		String levelName = level == 1 ? "warning" : level == 2 ? "fatal" : "level-" + level;
		return "TLS_ALERT " + levelName + " " + alertName(description) + "(" + description + ")";
	}

	private static String alertName(int description) {
		return switch (description) {
		case 0 -> "close_notify";
		case 10 -> "unexpected_message";
		case 20 -> "bad_record_mac";
		case 22 -> "record_overflow";
		case 40 -> "handshake_failure";
		case 42 -> "bad_certificate";
		case 43 -> "unsupported_certificate";
		case 44 -> "certificate_revoked";
		case 45 -> "certificate_expired";
		case 46 -> "certificate_unknown";
		case 47 -> "illegal_parameter";
		case 48 -> "unknown_ca";
		case 49 -> "access_denied";
		case 50 -> "decode_error";
		case 51 -> "decrypt_error";
		case 70 -> "protocol_version";
		case 71 -> "insufficient_security";
		case 80 -> "internal_error";
		case 86 -> "inappropriate_fallback";
		case 90 -> "user_canceled";
		case 109 -> "missing_extension";
		case 110 -> "unsupported_extension";
		case 112 -> "unrecognized_name";
		case 116 -> "certificate_required";
		case 120 -> "no_application_protocol";
		default -> "unknown_alert";
		};
	}

	public static void showStatus(String name, int total, int part, AtomicInteger lastShowedNumber) {
		showStatus(name, total, part, lastShowedNumber, null);
	}

	public static void showStatus(String name, int total, int part, AtomicInteger lastShowedNumber, String detail) {
		if (total <= 0) {
			return;
		}

		float percentage = ((float) part / (float) total) * 100;
		int percentageRounded = Math.round(percentage);
		String progressMessage = detail == null ? percentageRounded + " %" : percentageRounded + " % - " + detail;
		FuzzerStatusRegistry.getInstance().update(name, part, progressMessage);

		if ((percentageRounded % 5 == 0 || percentageRounded == 100 || percentageRounded == 99)
				&& logger.isLoggable(Level.INFO)) {
			if (lastShowedNumber.getAndSet(percentageRounded) != percentageRounded) {
				String message = String.format("%s %s %%", name, percentageRounded);
				logger.info(message);
				TLSSystemTray.getInstance().showInfoMessage(name, message);
			}
		}
	}
}
