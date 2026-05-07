package tech.cybersword.tls.fuzzer.dashboard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.awt.image.BufferedImage;
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
import java.util.TreeMap;
import java.util.zip.DeflaterOutputStream;

import javax.imageio.ImageIO;

import tech.cybersword.tls.fuzzer.controller.TLSController.TestSuite;

public class TLSReportCreator {

	private static final DateTimeFormatter FILE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
			.withZone(ZoneId.systemDefault());
	private static final DateTimeFormatter REPORT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
			.withZone(ZoneId.systemDefault());
	private static final String RFC_5246_URL = "https://www.rfc-editor.org/rfc/rfc5246.txt";
	private static final String RFC_8446_URL = "https://www.rfc-editor.org/rfc/rfc8446.txt";
	private static final String REPORT_FOOTER_URL = "https://cybersword.tech";
	private static final Path REPORT_LOGO = Path.of("pics", "TLSFuzzerLogo.png");
	private static final int PAGE_WIDTH = 612;
	private static final int PAGE_HEIGHT = 792;
	private static final int LINES_PER_PAGE = 34;

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
		lines.add("Brand: " + REPORT_FOOTER_URL);
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
			addFlowSection(lines);
			lines.add("");
			lines.add("Recent log entries:");
		int fromIndex = Math.max(0, logs.size() - 18);
		for (String log : logs.subList(fromIndex, logs.size())) {
			lines.add(log);
		}
			return writePdf(lines);
		}

	private void addFlowSection(List<String> lines) {
		Map<String, TLSHandshakeStepStatus> runtime = new java.util.HashMap<>();
		for (TLSHandshakeStepStatus status : FuzzerStatusRegistry.getInstance().handshakeStepSnapshot()) {
			runtime.put(status.key(), status);
		}
		lines.add("");
		lines.add("TLS 1.3 protocol flow:");
		addFlowLines(lines, TLSHandshakeFlows.tls13(), runtime);
		lines.add("");
		lines.add("TLS 1.2 protocol flow:");
		addFlowLines(lines, TLSHandshakeFlows.tls12(), runtime);
		lines.add("");
		lines.add("Flow legend: client, server, key schedule, record protection/wrapper, application.");
	}

	private void addFlowLines(List<String> lines, List<TLSHandshakeStep> steps, Map<String, TLSHandshakeStepStatus> runtime) {
		for (TLSHandshakeStep step : steps) {
			TLSHandshakeStepStatus status = runtime.get(TLSHandshakeStepStatus.key(step.protocol(), step.sequence()));
			String state = status == null ? (step.implemented() ? "READY" : "PLANNED") : status.state();
			String response = status == null ? "" : " | " + status.responseSummary() + " | request/response bytes "
					+ status.requestBytes() + "/" + status.responseBytes();
			lines.add(step.displayName() + " | " + step.category() + " | " + state + response);
		}
	}

	private String formatTime(long epochMillis) {
		if (epochMillis <= 0) {
			return "-";
		}
		return REPORT_FORMATTER.format(Instant.ofEpochMilli(epochMillis));
	}

	private byte[] writePdf(List<String> lines) throws IOException {
		PdfImage logo = loadLogo();
		List<List<String>> pages = pages(lines);
		Map<Integer, PdfObject> objects = new LinkedHashMap<>();
		List<Integer> pageObjectIds = new ArrayList<>();

		int catalogId = 1;
		int pagesId = 2;
		int fontId = 3;
		int logoId = 4;
		int nextId = 5;

		objects.put(catalogId, PdfObject.text("<< /Type /Catalog /Pages " + pagesId + " 0 R >>"));
		objects.put(fontId, PdfObject.text("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"));
		objects.put(logoId, PdfObject.binary(imageObject(logo)));

		for (int i = 0; i < pages.size(); i++) {
			int pageId = nextId++;
			int contentId = nextId++;
			int footerLinkId = nextId++;
			pageObjectIds.add(pageId);
			objects.put(pageId, PdfObject.text("<< /Type /Page /Parent " + pagesId + " 0 R /MediaBox [0 0 "
					+ PAGE_WIDTH + " " + PAGE_HEIGHT + "] /Resources << /Font << /F1 " + fontId
					+ " 0 R >> /XObject << /Logo " + logoId + " 0 R >> >> /Contents " + contentId
					+ " 0 R /Annots [" + footerLinkId + " 0 R] >>"));
			byte[] content = pageContent(pages.get(i), i + 1, pages.size());
			objects.put(contentId, PdfObject.text("<< /Length " + content.length + " >>\nstream\n"
					+ new String(content, StandardCharsets.US_ASCII) + "endstream"));
			objects.put(footerLinkId, PdfObject.text(linkAnnotation(REPORT_FOOTER_URL, 50, 23, 190, 38)));
		}

		StringBuilder kids = new StringBuilder();
		for (int pageObjectId : pageObjectIds) {
			kids.append(pageObjectId).append(" 0 R ");
		}
		objects.put(pagesId, PdfObject.text("<< /Type /Pages /Kids [" + kids + "] /Count " + pageObjectIds.size()
				+ " >>"));

		return writeObjects(objects, catalogId);
	}

	private List<List<String>> pages(List<String> lines) {
		List<List<String>> pages = new ArrayList<>();
		for (int i = 0; i < lines.size(); i += LINES_PER_PAGE) {
			pages.add(lines.subList(i, Math.min(lines.size(), i + LINES_PER_PAGE)));
		}
		if (pages.isEmpty()) {
			pages.add(List.of(""));
		}
		return pages;
	}

	private byte[] pageContent(List<String> lines, int pageNumber, int pageCount) {
		StringBuilder content = new StringBuilder();
		content.append("q\n56 0 0 56 50 708 cm\n/Logo Do\nQ\n");
		content.append("BT\n/F1 16 Tf\n112 738 Td\n(TLS Fuzzer Report) Tj\n");
		content.append("/F1 9 Tf\n0 -16 Td\n(").append(escapePdfText(REPORT_FOOTER_URL)).append(") Tj\nET\n");
		content.append("BT\n/F1 10 Tf\n50 670 Td\n");
		for (String line : lines) {
			content.append('(').append(escapePdfText(line)).append(") Tj\n");
			content.append("0 -15 Td\n");
		}
		content.append("ET\n");
		content.append("BT\n/F1 9 Tf\n50 32 Td\n(").append(escapePdfText(REPORT_FOOTER_URL)).append(") Tj\n");
		content.append("360 0 Td\n(Page ").append(pageNumber).append(" / ").append(pageCount).append(") Tj\n");
		content.append("ET\n");
		return content.toString().getBytes(StandardCharsets.US_ASCII);
	}

	private byte[] imageObject(PdfImage image) throws IOException {
		ByteArrayOutputStream object = new ByteArrayOutputStream();
		object.write(("<< /Type /XObject /Subtype /Image /Width " + image.width + " /Height " + image.height
				+ " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length "
				+ image.compressedRgb.length + " >>\nstream\n").getBytes(StandardCharsets.US_ASCII));
		object.write(image.compressedRgb);
		object.write("\nendstream".getBytes(StandardCharsets.US_ASCII));
		return object.toByteArray();
	}

	private PdfImage loadLogo() throws IOException {
		BufferedImage image = ImageIO.read(REPORT_LOGO.toFile());
		if (image == null) {
			throw new IOException("Could not read report logo " + REPORT_LOGO);
		}
		ByteArrayOutputStream rawRgb = new ByteArrayOutputStream(image.getWidth() * image.getHeight() * 3);
		for (int y = 0; y < image.getHeight(); y++) {
			for (int x = 0; x < image.getWidth(); x++) {
				int rgb = image.getRGB(x, y);
				rawRgb.write((rgb >>> 16) & 0xff);
				rawRgb.write((rgb >>> 8) & 0xff);
				rawRgb.write(rgb & 0xff);
			}
		}
		ByteArrayOutputStream compressed = new ByteArrayOutputStream();
		try (DeflaterOutputStream deflater = new DeflaterOutputStream(compressed)) {
			deflater.write(rawRgb.toByteArray());
		}
		return new PdfImage(image.getWidth(), image.getHeight(), compressed.toByteArray());
	}

	private byte[] writeObjects(Map<Integer, PdfObject> objects, int catalogId) throws IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write("%PDF-1.4\n".getBytes(StandardCharsets.US_ASCII));
		Map<Integer, Integer> offsets = new TreeMap<>();
		for (Map.Entry<Integer, PdfObject> object : new TreeMap<>(objects).entrySet()) {
			offsets.put(object.getKey(), output.size());
			output.write((object.getKey() + " 0 obj\n").getBytes(StandardCharsets.US_ASCII));
			output.write(object.getValue().data());
			output.write("\nendobj\n".getBytes(StandardCharsets.US_ASCII));
		}
		int xrefOffset = output.size();
		int maxObjectId = offsets.keySet().stream().mapToInt(Integer::intValue).max().orElse(0);
		output.write(("xref\n0 " + (maxObjectId + 1) + "\n").getBytes(StandardCharsets.US_ASCII));
		output.write("0000000000 65535 f \n".getBytes(StandardCharsets.US_ASCII));
		for (int objectId = 1; objectId <= maxObjectId; objectId++) {
			Integer offset = offsets.get(objectId);
			if (offset == null) {
				output.write("0000000000 65535 f \n".getBytes(StandardCharsets.US_ASCII));
			} else {
				output.write(String.format("%010d 00000 n \n", offset).getBytes(StandardCharsets.US_ASCII));
			}
		}
		output.write(("trailer\n<< /Size " + (maxObjectId + 1) + " /Root " + catalogId
				+ " 0 R >>\nstartxref\n" + xrefOffset + "\n%%EOF\n").getBytes(StandardCharsets.US_ASCII));
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

	private record PdfImage(int width, int height, byte[] compressedRgb) {
	}

	private record PdfObject(byte[] data) {

		private static PdfObject text(String value) {
			return new PdfObject(value.getBytes(StandardCharsets.US_ASCII));
		}

		private static PdfObject binary(byte[] value) {
			return new PdfObject(value);
		}
	}
}
