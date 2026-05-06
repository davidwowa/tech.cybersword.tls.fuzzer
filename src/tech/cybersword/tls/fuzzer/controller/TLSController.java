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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort, vector.getData());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(vector.getName() + " response " + StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, vectors.size(), i + 1, lastStatus, vector.getName());
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format("%s: error on vector %s %s", jobName, vector.getName(), e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							RandomUtil.getInstance()
									.generateRandomArray(CommonProperties.getInstance().getRandomArraySize()));
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(
								String.format("simpleTLSRandomFixArray: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							RandomUtil.getInstance().generateRandomArray(randomNumber));
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format("simpleTLSRandomArray: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							TLS12TestDataGenerator.getInstance().generateExampleTLSHello());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format("simpleTLS12HelloTest: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							TLS12TestDataGenerator.getInstance().generateExampleTLSHelloRandomExtensionData());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format(
								"simpleTLS12HelloRandomExtensionTest: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							TLS13TestDataGenerator.getInstance().generateExampleTLSHello());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
					// TODO get status from ExecutorService is maybe better way...
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format("simpleTLS13HelloTest: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							TLS13TestDataGenerator.getInstance().generateExampleTLSHelloRandomExtensionData());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String
								.format("simpleTLS13HelloRandomExtensionTest: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
					byte[] response = client.sendTLSMessage(tlsHost, tlsPort,
							TLS13TestDataGenerator.getInstance().generateExampleTLSRHelloRandomExtensionData());
					if (response.length != 0 && logger.isLoggable(Level.INFO)) {
						logger.info(StringUtil.getInstance().toHexString(response));
					}
					showStatus(jobName, amountTLSRequests, i + 1, lastStatus);
				} catch (Exception e) {
					if (logger.isLoggable(Level.SEVERE)) {
						logger.severe(String.format(
								"simpleTLS13RHelloRandomExtensionTest: error tls fuzzer test number %s %s", i, e));
					}
					e.printStackTrace();
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
