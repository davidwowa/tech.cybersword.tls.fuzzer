package tech.cybersword.tls.fuzzer.dashboard;

public record TLSHandshakeStepStatus(String protocol, int sequence, String state, String jobName, int iteration,
		int requestBytes, int responseBytes, String responseSummary, long updatedAt) {

	public String key() {
		return key(protocol, sequence);
	}

	public static String key(String protocol, int sequence) {
		return protocol + ":" + sequence;
	}
}
