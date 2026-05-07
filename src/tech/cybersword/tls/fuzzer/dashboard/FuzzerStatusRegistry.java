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
	private final Map<String, TLSHandshakeStepStatus> handshakeStepStatuses = new ConcurrentHashMap<>();
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
		statuses.computeIfPresent(name, (key, status) -> status.getState() == State.FAILED ? status
				: status.withState(State.EXECUTED, "executed"));
		FuzzerTestStatus status = statuses.get(name);
		addLog(name + (status != null && status.getState() == State.FAILED ? " ended with failures" : " executed"));
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

	public void recordHandshakeStep(TLSHandshakeStep step, String state, String jobName, int iteration, int requestBytes,
			int responseBytes, String responseSummary) {
		if (step == null) {
			return;
		}
		handshakeStepStatuses.put(TLSHandshakeStepStatus.key(step.protocol(), step.sequence()),
				new TLSHandshakeStepStatus(step.protocol(), step.sequence(), state, jobName, iteration, requestBytes,
						responseBytes, responseSummary, System.currentTimeMillis()));
	}

	public List<TLSHandshakeStepStatus> handshakeStepSnapshot() {
		List<TLSHandshakeStepStatus> snapshot = new ArrayList<>(handshakeStepStatuses.values());
		snapshot.sort(Comparator.comparing(TLSHandshakeStepStatus::protocol).thenComparing(TLSHandshakeStepStatus::sequence));
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

	public List<String> serverResponseLogSnapshot() {
		List<String> responses = new ArrayList<>();
		for (String message : logMessages) {
			if (isVisibleServerResponse(message)) {
				responses.add(message);
			}
		}
		return responses;
	}

	public int noResponseLogCount() {
		int count = 0;
		for (String message : logMessages) {
			if (message.contains("Server Response") && message.contains("classification=NO_RESPONSE")) {
				count++;
			}
		}
		return count;
	}

	private boolean isVisibleServerResponse(String message) {
		return message.contains("Server Response") && !message.contains("classification=NO_RESPONSE");
	}

	public void clear() {
		statuses.clear();
		handshakeStepStatuses.clear();
		logMessages.clear();
	}
}
