package tech.cybersword.tls.fuzzer.dashboard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

import tech.cybersword.tls.fuzzer.dashboard.FuzzerTestStatus.State;

public class FuzzerStatusRegistry {

	private static FuzzerStatusRegistry instance;

	private final Map<String, FuzzerTestStatus> statuses = new ConcurrentHashMap<>();
	private final Deque<String> logMessages = new ConcurrentLinkedDeque<>();

	private FuzzerStatusRegistry() {
	}

	public static FuzzerStatusRegistry getInstance() {
		if (instance == null) {
			instance = new FuzzerStatusRegistry();
		}
		return instance;
	}

	public void start(String name, int total) {
		long now = System.currentTimeMillis();
		statuses.put(name, new FuzzerTestStatus(name, total, 0, State.RUNNING, now, now, "started"));
		addLog(name + " started, total=" + total);
	}

	public void update(String name, int completed, String message) {
		statuses.computeIfPresent(name, (key, status) -> status.withProgress(completed, message));
	}

	public void success(String name) {
		statuses.computeIfPresent(name, (key, status) -> status.withState(State.SUCCESS, "completed"));
		addLog(name + " completed");
	}

	public void failed(String name, Exception exception) {
		String message = exception == null ? "failed" : exception.getClass().getSimpleName() + ": " + exception.getMessage();
		statuses.computeIfPresent(name, (key, status) -> status.withState(State.FAILED, message));
		addLog(name + " failed: " + message);
	}

	public List<FuzzerTestStatus> snapshot() {
		List<FuzzerTestStatus> snapshot = new ArrayList<>(statuses.values());
		snapshot.sort(Comparator.comparing(FuzzerTestStatus::getStartedAt).thenComparing(FuzzerTestStatus::getName));
		return snapshot;
	}

	public void addLog(String message) {
		logMessages.addLast(System.currentTimeMillis() + " " + message);
		while (logMessages.size() > 500) {
			logMessages.pollFirst();
		}
	}

	public List<String> logSnapshot() {
		return new ArrayList<>(logMessages);
	}

	public void clear() {
		statuses.clear();
		logMessages.clear();
	}
}
