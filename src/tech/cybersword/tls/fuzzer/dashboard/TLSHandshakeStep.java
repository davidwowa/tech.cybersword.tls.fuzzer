package tech.cybersword.tls.fuzzer.dashboard;

public record TLSHandshakeStep(String protocol, int sequence, String actor, String category, String title,
		String description, String color, boolean implemented) {

	public String id() {
		return protocol + "-" + sequence;
	}

	public String displayName() {
		String owner = actor == null || actor.isBlank() ? "shared" : actor;
		return sequence + ". (" + owner + ") " + title;
	}
}
