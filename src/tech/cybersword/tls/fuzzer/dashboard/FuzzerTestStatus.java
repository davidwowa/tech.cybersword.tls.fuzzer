package tech.cybersword.tls.fuzzer.dashboard;

public class FuzzerTestStatus {

	public enum State {
		PENDING,
		RUNNING,
		SUCCESS,
		FAILED
	}

	private final String name;
	private final int total;
	private final int completed;
	private final State state;
	private final long startedAt;
	private final long updatedAt;
	private final String message;

	public FuzzerTestStatus(String name, int total, int completed, State state, long startedAt, long updatedAt,
			String message) {
		this.name = name;
		this.total = total;
		this.completed = completed;
		this.state = state;
		this.startedAt = startedAt;
		this.updatedAt = updatedAt;
		this.message = message;
	}

	public String getName() {
		return name;
	}

	public int getTotal() {
		return total;
	}

	public int getCompleted() {
		return completed;
	}

	public State getState() {
		return state;
	}

	public long getStartedAt() {
		return startedAt;
	}

	public long getUpdatedAt() {
		return updatedAt;
	}

	public String getMessage() {
		return message;
	}

	public int getProgressPercentage() {
		if (total <= 0) {
			return 0;
		}
		return Math.min(100, Math.round(((float) completed / (float) total) * 100));
	}

	public FuzzerTestStatus withProgress(int completed, String message) {
		return new FuzzerTestStatus(name, total, completed, State.RUNNING, startedAt, System.currentTimeMillis(), message);
	}

	public FuzzerTestStatus withState(State state, String message) {
		int completedCount = state == State.SUCCESS ? total : completed;
		return new FuzzerTestStatus(name, total, completedCount, state, startedAt, System.currentTimeMillis(), message);
	}
}
