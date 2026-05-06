package tech.cybersword.tls.fuzzer.dashboard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tech.cybersword.tls.fuzzer.controller.TLSController.TestSuite;

public class TLSReportCreator {

	private static final DateTimeFormatter FILE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
			.withZone(ZoneId.systemDefault());
	private static final DateTimeFormatter REPORT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
			.withZone(ZoneId.systemDefault());
	private static final String RFC_5246_URL = "https://www.rfc-editor.org/rfc/rfc5246.txt";
	private static final String RFC_8446_URL = "https://www.rfc-editor.org/rfc/rfc8446.txt";

	private static TLSReportCreator instance;

	private volatile Path latestReportPath;

	private TLSReportCreator() {
	}

	public static TLSReportCreator getInstance() {
		if (instance == null) {
			instance = new TLSReportCreator();
		}
		return instance;
	}

	public Path createReport(String host, int port, TestSuite suite, long startedAt, long endedAt,
			List<FuzzerTestStatus> statuses, List<String> logs) throws IOException {
		Files.createDirectories(Path.of("reports"));
		Path reportPath = Path.of("reports", "tls-fuzzer-report-" + FILE_FORMATTER.format(Instant.ofEpochMilli(endedAt))
				+ ".pdf");
		byte[] pdf = createPdf(host, port, suite, startedAt, endedAt, statuses, logs);
		Files.write(reportPath, pdf);
		latestReportPath = reportPath;
		FuzzerStatusRegistry.getInstance().addLog("pdf report created: " + reportPath);
		return reportPath;
	}

	public Path latestReportPath() {
		return latestReportPath;
	}

	private byte[] createPdf(String host, int port, TestSuite suite, long startedAt, long endedAt,
			List<FuzzerTestStatus> statuses, List<String> logs) throws IOException {
		List<String> lines = new ArrayList<>();
		long totalTests = statuses.stream().mapToLong(FuzzerTestStatus::getTotal).sum();
		long completedTests = statuses.stream().mapToLong(FuzzerTestStatus::getCompleted).sum();
		long failedJobs = statuses.stream().filter(status -> status.getState() == FuzzerTestStatus.State.FAILED).count();
		long runningJobs = statuses.stream().filter(status -> status.getState() == FuzzerTestStatus.State.RUNNING).count();
		String conclusion = failedJobs == 0 && runningJobs == 0
				? "Conclusion: TLS fuzzing run completed without failed dashboard jobs."
				: "Conclusion: TLS fuzzing run needs review; failed or interrupted jobs were recorded.";

		lines.add("TLS Fuzzer Report");
		lines.add("Brand: https://cyberswor.tech");
		lines.add("Target: " + host + ":" + port);
		lines.add("Started as suite: " + suite);
		lines.add("Started at: " + formatTime(startedAt));
		lines.add("Ended at: " + formatTime(endedAt));
		lines.add("Total configured test messages: " + totalTests);
		lines.add("Completed test messages: " + completedTests);
		lines.add("Dashboard jobs: " + statuses.size());
		lines.add("Failed jobs: " + failedJobs);
		lines.add("TLS RFC 5246: " + RFC_5246_URL);
		lines.add("TLS RFC 8446: " + RFC_8446_URL);
		lines.add(conclusion);
		lines.add("");
		lines.add("Job summary:");
		for (FuzzerTestStatus status : statuses) {
			lines.add(status.getName() + " | " + status.getState() + " | " + status.getCompleted() + " / "
					+ status.getTotal() + " | " + status.getMessage());
		}
		lines.add("");
		lines.add("Recent log entries:");
		int fromIndex = Math.max(0, logs.size() - 18);
		for (String log : logs.subList(fromIndex, logs.size())) {
			lines.add(log);
		}
		return writeSinglePagePdf(lines);
	}

	private String formatTime(long epochMillis) {
		if (epochMillis <= 0) {
			return "-";
		}
		return REPORT_FORMATTER.format(Instant.ofEpochMilli(epochMillis));
	}

	private byte[] writeSinglePagePdf(List<String> lines) throws IOException {
		List<String> visibleLines = lines.stream().limit(46).toList();
		StringBuilder content = new StringBuilder();
		content.append("BT\n/F1 16 Tf\n50 742 Td\n");
		for (int i = 0; i < visibleLines.size(); i++) {
			if (i == 1) {
				content.append("/F1 10 Tf\n");
			}
			content.append('(').append(escapePdfText(visibleLines.get(i))).append(") Tj\n");
			content.append("0 -15 Td\n");
		}
		content.append("ET\n");

		byte[] stream = content.toString().getBytes(StandardCharsets.US_ASCII);
		Map<Integer, String> objects = new LinkedHashMap<>();
		objects.put(1, "<< /Type /Catalog /Pages 2 0 R >>");
		objects.put(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
		objects.put(3,
				"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots [6 0 R 7 0 R] >>");
		objects.put(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
		objects.put(5, "<< /Length " + stream.length + " >>\nstream\n"
				+ new String(stream, StandardCharsets.US_ASCII) + "endstream");
		objects.put(6, linkAnnotation(RFC_5246_URL, 50, 587, 340, 601));
		objects.put(7, linkAnnotation(RFC_8446_URL, 50, 572, 340, 586));

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write("%PDF-1.4\n".getBytes(StandardCharsets.US_ASCII));
		List<Integer> offsets = new ArrayList<>();
		offsets.add(0);
		for (Map.Entry<Integer, String> object : objects.entrySet()) {
			offsets.add(output.size());
			output.write((object.getKey() + " 0 obj\n").getBytes(StandardCharsets.US_ASCII));
			output.write(object.getValue().getBytes(StandardCharsets.US_ASCII));
			output.write("\nendobj\n".getBytes(StandardCharsets.US_ASCII));
		}
		int xrefOffset = output.size();
		output.write(("xref\n0 " + (objects.size() + 1) + "\n").getBytes(StandardCharsets.US_ASCII));
		output.write("0000000000 65535 f \n".getBytes(StandardCharsets.US_ASCII));
		for (int i = 1; i < offsets.size(); i++) {
			output.write(String.format("%010d 00000 n \n", offsets.get(i)).getBytes(StandardCharsets.US_ASCII));
		}
		output.write(("trailer\n<< /Size " + (objects.size() + 1) + " /Root 1 0 R >>\nstartxref\n" + xrefOffset
				+ "\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));
		return output.toByteArray();
	}

	private String linkAnnotation(String url, int left, int bottom, int right, int top) {
		return "<< /Type /Annot /Subtype /Link /Rect [" + left + " " + bottom + " " + right + " " + top
				+ "] /Border [0 0 0] /A << /S /URI /URI (" + escapePdfText(url) + ") >> >>";
	}

	private String escapePdfText(String value) {
		return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\r", " ")
				.replace("\n", " ");
	}
}
