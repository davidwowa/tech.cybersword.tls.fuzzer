package tech.cybersword.tls.fuzzer.dashboard;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import tech.cybersword.tls.fuzzer.controller.TLSController.TestSuite;
import tech.cybersword.tls.fuzzer.dashboard.FuzzerTestStatus.State;

class TLSReportCreatorTest {

	@Test
	void createsPdfReportWithTargetAndRfcLinks() throws Exception {
		FuzzerTestStatus status = new FuzzerTestStatus("rfcByteStreamSuite:record-header", 42, 42, State.EXECUTED,
				System.currentTimeMillis() - 1000, System.currentTimeMillis(), "executed");

		Path report = TLSReportCreator.getInstance().createReport("127.0.0.1", 443, TestSuite.RFC,
				System.currentTimeMillis() - 1000, System.currentTimeMillis(), List.of(status),
				List.of("suite=RFC target=127.0.0.1:443 started"));

		String pdf = Files.readString(report, StandardCharsets.ISO_8859_1);

		assertTrue(pdf.startsWith("%PDF-1.4"));
		assertTrue(pdf.contains("Target: 127.0.0.1:443"));
		assertTrue(pdf.contains("/Logo Do"));
		assertTrue(pdf.contains("/Subtype /Image"));
		assertTrue(pdf.contains("https://cybersword.tech"));
		assertTrue(pdf.contains("https://www.rfc-editor.org/rfc/rfc5246.txt"));
		assertTrue(pdf.contains("https://www.rfc-editor.org/rfc/rfc8446.txt"));
	}

	@Test
	void createsMultiPageReportForManyJobsAndLogs() throws Exception {
		List<FuzzerTestStatus> statuses = new ArrayList<>();
		for (int i = 0; i < 40; i++) {
			statuses.add(new FuzzerTestStatus("job-" + i, 100, 100, State.EXECUTED, System.currentTimeMillis() - 1000,
					System.currentTimeMillis(), "executed"));
		}
		List<String> logs = new ArrayList<>();
		for (int i = 0; i < 40; i++) {
			logs.add("Server Response job=job-" + i + " bytes=7 classification=TLS_ALERT fatal decode_error(50)");
		}

		Path report = TLSReportCreator.getInstance().createReport("127.0.0.1", 443, TestSuite.RFC,
				System.currentTimeMillis() - 1000, System.currentTimeMillis(), statuses, logs);

		String pdf = Files.readString(report, StandardCharsets.ISO_8859_1);

		assertTrue(pdf.contains("Page 1 / "));
		assertTrue(pdf.contains("Page 2 / "));
		assertTrue(pdf.contains("/Logo Do"));
		assertTrue(pdf.contains("https://cybersword.tech"));
	}
}
