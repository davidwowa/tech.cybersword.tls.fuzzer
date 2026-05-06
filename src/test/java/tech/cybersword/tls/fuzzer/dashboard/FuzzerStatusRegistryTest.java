package tech.cybersword.tls.fuzzer.dashboard;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import tech.cybersword.tls.fuzzer.dashboard.FuzzerTestStatus.State;

class FuzzerStatusRegistryTest {

	@Test
	void tracksRunningAndCompletedStatus() {
		FuzzerStatusRegistry registry = FuzzerStatusRegistry.getInstance();
		registry.clear();

		registry.start("tls13", 10);
		registry.update("tls13", 4, "40 %");

		FuzzerTestStatus running = registry.snapshot().get(0);
		assertEquals(State.RUNNING, running.getState());
		assertEquals(40, running.getProgressPercentage());

		registry.success("tls13");

		FuzzerTestStatus completed = registry.snapshot().get(0);
		assertEquals(State.SUCCESS, completed.getState());
		assertEquals(100, completed.getProgressPercentage());
	}
}
