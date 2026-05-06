package tech.cybersword.tls.fuzzer.dashboard;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import tech.cybersword.tls.fuzzer.common.CommonProperties;
import tech.cybersword.tls.fuzzer.controller.TLSController;
import tech.cybersword.tls.fuzzer.controller.TLSController.TestSuite;
import tech.cybersword.tls.fuzzer.generator.TLSFuzzVector;
import tech.cybersword.tls.fuzzer.generator.TLSProtocolDataGenerator;
import tech.cybersword.tls.fuzzer.util.LoggerUtil;

public class BrowserDashboardServer {

	private static final Logger logger = LoggerUtil.getLogger(BrowserDashboardServer.class.getName());

	private static BrowserDashboardServer instance;

	private HttpServer server;
	private String baseUrl;

	private BrowserDashboardServer() {
	}

	public static BrowserDashboardServer getInstance() {
		if (instance == null) {
			instance = new BrowserDashboardServer();
		}
		return instance;
	}

	public synchronized void start() {
		if (!CommonProperties.isBrowserDashboardEnabled() || server != null) {
			return;
		}
		try {
			int port = CommonProperties.getBrowserDashboardPort();
			server = CommonProperties.isBrowserDashboardHttpsEnabled() ? createHttpsServer(port) : HttpServer.create(
					new InetSocketAddress(port), 0);
			server.createContext("/", new IndexHandler());
			server.createContext("/api/status", new StatusHandler());
			server.createContext("/api/vectors", new VectorsHandler());
			server.createContext("/api/start", new StartHandler());
			server.createContext("/api/stop", new StopHandler());
			server.createContext("/api/report", new ReportHandler());
			server.createContext("/api/health", exchange -> send(exchange, 200, "application/json", "{\"status\":\"ok\"}"));
			server.setExecutor(Executors.newCachedThreadPool());
			server.start();
			baseUrl = (server instanceof HttpsServer ? "https" : "http") + "://localhost:" + port + "/";
			if (logger.isLoggable(Level.INFO)) {
				logger.info("Browser dashboard started at " + baseUrl);
			}
		} catch (Exception e) {
			if (logger.isLoggable(Level.SEVERE)) {
				logger.log(Level.SEVERE, "Could not start browser dashboard", e);
			}
		}
	}

	public synchronized void stop() {
		if (server != null) {
			server.stop(0);
			server = null;
			baseUrl = null;
		}
	}

	public String getBaseUrl() {
		return baseUrl;
	}

	private HttpServer createHttpsServer(int port) throws Exception {
		String keyStorePath = CommonProperties.getBrowserDashboardKeyStorePath();
		String keyStorePassword = CommonProperties.getBrowserDashboardKeyStorePassword();
		if (keyStorePath == null || keyStorePath.isBlank()) {
			throw new IllegalStateException("dashboard.browser.https.keystore must be set when HTTPS is enabled");
		}
		char[] password = keyStorePassword == null ? new char[0] : keyStorePassword.toCharArray();
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (var inputStream = java.nio.file.Files.newInputStream(java.nio.file.Path.of(keyStorePath))) {
			keyStore.load(inputStream, password);
		}
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, password);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

		HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(port), 0);
		httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
		return httpsServer;
	}

	private static class IndexHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			send(exchange, 200, "text/html; charset=utf-8", indexHtml());
		}
	}

	private static class StatusHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			List<FuzzerTestStatus> statuses = FuzzerStatusRegistry.getInstance().snapshot();
			List<String> logs = FuzzerStatusRegistry.getInstance().logSnapshot();
			TLSController controller = TLSController.getInstance();
			StringBuilder json = new StringBuilder();
			json.append("{\"generatedAt\":\"").append(Instant.now()).append("\",");
			json.append("\"running\":").append(controller.isRunning()).append(',');
			json.append("\"host\":\"").append(json(controller.getTargetHost())).append("\",");
			json.append("\"port\":").append(controller.getTargetPort()).append(',');
			json.append("\"suite\":\"").append(controller.getActiveSuite()).append("\",");
			Path latestReportPath = TLSReportCreator.getInstance().latestReportPath();
			json.append("\"latestReport\":\"").append(json(latestReportPath == null ? "" : latestReportPath.toString()))
					.append("\",");
			json.append("\"tests\":[");
			for (int i = 0; i < statuses.size(); i++) {
				FuzzerTestStatus status = statuses.get(i);
				if (i > 0) {
					json.append(',');
				}
				json.append('{');
				json.append("\"name\":\"").append(json(status.getName())).append("\",");
				json.append("\"state\":\"").append(status.getState()).append("\",");
				json.append("\"total\":").append(status.getTotal()).append(',');
				json.append("\"completed\":").append(status.getCompleted()).append(',');
				json.append("\"progress\":").append(status.getProgressPercentage()).append(',');
				json.append("\"startedAt\":").append(status.getStartedAt()).append(',');
				json.append("\"updatedAt\":").append(status.getUpdatedAt()).append(',');
				json.append("\"message\":\"").append(json(status.getMessage())).append("\"");
				json.append('}');
			}
			json.append("],\"logs\":[");
			for (int i = 0; i < logs.size(); i++) {
				if (i > 0) {
					json.append(',');
				}
				json.append("\"").append(json(logs.get(i))).append("\"");
			}
			json.append("]}");
			send(exchange, 200, "application/json", json.toString());
		}
	}

	private static class StartHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				send(exchange, 405, "application/json", "{\"error\":\"POST required\"}");
				return;
			}
			Map<String, String> form = readForm(exchange);
			String host = form.getOrDefault("host", CommonProperties.getInstance().getTlsHost());
			int port = parseInt(form.get("port"), CommonProperties.getInstance().getTlsPort());
			TestSuite suite = parseSuite(form.get("suite"));
			boolean started = TLSController.getInstance().startTests(host, port, suite);
			send(exchange, 200, "application/json", "{\"started\":" + started + "}");
		}
	}

	private static class StopHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				send(exchange, 405, "application/json", "{\"error\":\"POST required\"}");
				return;
			}
			TLSController.getInstance().stopTests();
			send(exchange, 200, "application/json", "{\"stopped\":true}");
		}
	}

	private static class VectorsHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			List<TLSFuzzVector> vectors = TLSProtocolDataGenerator.getInstance().createRfcByteStreamVectors();
			Map<String, Integer> categories = new java.util.LinkedHashMap<>();
			for (TLSFuzzVector vector : vectors) {
				categories.merge(vector.getCategory(), 1, Integer::sum);
			}
			StringBuilder json = new StringBuilder();
			json.append("{\"count\":").append(vectors.size()).append(",\"categories\":[");
			int categoryIndex = 0;
			for (Map.Entry<String, Integer> entry : categories.entrySet()) {
				if (categoryIndex++ > 0) {
					json.append(',');
				}
				json.append('{');
				json.append("\"name\":\"").append(json(entry.getKey())).append("\",");
				json.append("\"count\":").append(entry.getValue());
				json.append('}');
			}
			json.append("],\"vectors\":[");
			for (int i = 0; i < vectors.size(); i++) {
				TLSFuzzVector vector = vectors.get(i);
				if (i > 0) {
					json.append(',');
				}
				json.append('{');
				json.append("\"name\":\"").append(json(vector.getName())).append("\",");
				json.append("\"category\":\"").append(json(vector.getCategory())).append("\",");
				json.append("\"rfc\":\"").append(json(vector.getRfc())).append("\",");
				json.append("\"description\":\"").append(json(vector.getDescription())).append("\",");
				json.append("\"bytes\":").append(vector.size());
				json.append('}');
			}
			json.append("]}");
			send(exchange, 200, "application/json", json.toString());
		}
	}

	private static class ReportHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
				send(exchange, 405, "application/json", "{\"error\":\"GET required\"}");
				return;
			}
			TLSController controller = TLSController.getInstance();
			Path reportPath = TLSReportCreator.getInstance().latestReportPath();
			if (reportPath == null || !Files.exists(reportPath)) {
				reportPath = TLSReportCreator.getInstance().createReport(controller.getTargetHost(),
						controller.getTargetPort(), controller.getActiveSuite(), controller.getRunStartedAt(),
						System.currentTimeMillis(), FuzzerStatusRegistry.getInstance().snapshot(),
						FuzzerStatusRegistry.getInstance().logSnapshot());
			}
			sendFile(exchange, reportPath);
		}
	}

	private static void send(HttpExchange exchange, int statusCode, String contentType, String body) throws IOException {
		byte[] data = body.getBytes(StandardCharsets.UTF_8);
		send(exchange, statusCode, contentType, data);
	}

	private static void send(HttpExchange exchange, int statusCode, String contentType, byte[] data) throws IOException {
		Headers headers = exchange.getResponseHeaders();
		headers.set("Content-Type", contentType);
		headers.set("Cache-Control", "no-store");
		exchange.sendResponseHeaders(statusCode, data.length);
		try (OutputStream outputStream = exchange.getResponseBody()) {
			outputStream.write(data);
		}
	}

	private static void sendFile(HttpExchange exchange, Path path) throws IOException {
		byte[] data = Files.readAllBytes(path);
		Headers headers = exchange.getResponseHeaders();
		headers.set("Content-Type", "application/pdf");
		headers.set("Cache-Control", "no-store");
		headers.set("Content-Disposition", "attachment; filename=\"" + path.getFileName() + "\"");
		exchange.sendResponseHeaders(200, data.length);
		try (OutputStream outputStream = exchange.getResponseBody()) {
			outputStream.write(data);
		}
	}

	private static String json(String value) {
		if (value == null) {
			return "";
		}
		return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
	}

	private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
		String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		Map<String, String> values = new HashMap<>();
		for (String pair : body.split("&")) {
			if (pair.isBlank()) {
				continue;
			}
			String[] parts = pair.split("=", 2);
			String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
			String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
			values.put(key, value);
		}
		return values;
	}

	private static int parseInt(String value, int defaultValue) {
		try {
			return Integer.parseInt(value);
		} catch (Exception e) {
			return defaultValue;
		}
	}

	private static TestSuite parseSuite(String value) {
		try {
			return TestSuite.valueOf(value);
		} catch (Exception e) {
			return TestSuite.ALL;
		}
	}

	private static String indexHtml() {
		return """
				<!doctype html>
				<html lang=\"en\">
				<head>
					<meta charset=\"utf-8\">
					<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
					<title>TLS Fuzzer Dashboard</title>
					<style>
						:root { color-scheme: dark; font-family: \"JetBrains Mono\", \"Cascadia Mono\", \"SFMono-Regular\", Consolas, monospace; }
						* { box-sizing: border-box; }
						body {
							margin: 0;
							min-height: 100vh;
							background:
								linear-gradient(rgba(0, 255, 136, .035) 1px, transparent 1px),
								linear-gradient(90deg, rgba(0, 255, 136, .035) 1px, transparent 1px),
								#020604;
							background-size: 18px 18px;
							color: #8dffb2;
							text-shadow: 0 0 8px rgba(37, 255, 124, .35);
						}
						body::before {
							content: \"\";
							position: fixed;
							inset: 0;
							pointer-events: none;
							background: repeating-linear-gradient(180deg, rgba(255,255,255,.05) 0, rgba(255,255,255,.05) 1px, transparent 1px, transparent 4px);
							mix-blend-mode: soft-light;
						}
						header { padding: 16px 24px; border-bottom: 1px solid #16a34a; background: rgba(0, 20, 10, .88); display: flex; justify-content: space-between; gap: 16px; align-items: center; flex-wrap: wrap; }
						h1 { margin: 0; font-size: 20px; letter-spacing: 0; text-transform: uppercase; }
						h1::before { content: \"root@tls-fuzzer:~$ \"; color: #d9ff5f; }
						.brand-link { color: #67e8f9; text-decoration: none; border: 1px solid #67e8f9; border-radius: 3px; padding: 6px 10px; text-shadow: 0 0 8px rgba(103,232,249,.35); }
						.brand-link:hover { background: rgba(103,232,249,.12); color: #d9ff5f; }
						main { padding: 18px 24px 32px; display: grid; gap: 18px; }
						.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
						.metric, .terminal {
							background: rgba(1, 18, 8, .9);
							border: 1px solid #15803d;
							border-radius: 4px;
							box-shadow: inset 0 0 18px rgba(22, 163, 74, .12), 0 0 18px rgba(22, 163, 74, .08);
						}
						.metric { padding: 12px 14px; }
						.metric span { color: #65d98b; font-size: 12px; text-transform: uppercase; }
						.metric strong { display: block; color: #d9ff5f; font-size: 26px; margin-top: 4px; }
						.controls { display: grid; grid-template-columns: 1fr 120px repeat(7, minmax(92px, auto)); gap: 10px; align-items: end; padding: 12px; }
						label { display: grid; gap: 5px; color: #65d98b; font-size: 12px; text-transform: uppercase; }
						input, select, button, .button-link {
							height: 36px;
							border-radius: 4px;
							border: 1px solid #22c55e;
							background: #03150b;
							color: #8dffb2;
							font: inherit;
						}
						input, select { padding: 0 10px; }
						button, .button-link { cursor: pointer; padding: 0 12px; text-transform: uppercase; display: inline-grid; place-items: center; text-decoration: none; }
						button:hover, .button-link:hover { background: #063d20; color: #d9ff5f; }
						button.stop { border-color: #ff6b6b; color: #ff9a9a; }
						table { width: 100%; border-collapse: collapse; table-layout: fixed; }
						th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid rgba(34, 197, 94, .22); font-size: 13px; vertical-align: top; word-break: break-word; }
						th { color: #d9ff5f; background: rgba(20, 83, 45, .32); text-transform: uppercase; font-size: 12px; }
						section { overflow: auto; }
						progress { width: 130px; height: 10px; accent-color: #22c55e; }
						.badge { border: 1px solid #22c55e; border-radius: 3px; padding: 2px 7px; color: #8dffb2; background: rgba(34,197,94,.12); }
						.SUCCESS { color: #d9ff5f; border-color: #d9ff5f; }
						.FAILED { color: #ff6b6b; border-color: #ff6b6b; }
						.RUNNING { color: #67e8f9; border-color: #67e8f9; }
						.note { color: #65d98b; padding: 10px; font-size: 12px; border-bottom: 1px solid rgba(34, 197, 94, .22); }
						.log-view { margin: 0; padding: 12px; max-height: 260px; overflow: auto; white-space: pre-wrap; color: #67e8f9; font-size: 12px; }
						.matrix-cell::before { content: \"[\"; color: #d9ff5f; }
						.matrix-cell::after { content: \"]\"; color: #d9ff5f; }
					</style>
				</head>
				<body>
					<header>
						<h1>TLS Fuzzer Dashboard</h1>
						<a class=\"brand-link\" href=\"https://cyberswor.tech\" target=\"_blank\" rel=\"noopener\">https://cyberswor.tech</a>
					</header>
					<main>
						<section class=\"summary\">
							<div class=\"metric\"><span>Tests</span><strong id=\"tests\">0</strong></div>
							<div class=\"metric\"><span>Running</span><strong id=\"running\">0</strong></div>
							<div class=\"metric\"><span>Vectors</span><strong id=\"vectors\">0</strong></div>
							<div class=\"metric\"><span>Updated</span><strong id=\"updated\">-</strong></div>
						</section>
						<section class=\"terminal controls\">
							<label>Target IP / Host<input id=\"host\" value=\"__HOST__\"></label>
							<label>Port<input id=\"port\" type=\"number\" min=\"1\" max=\"65535\" value=\"__PORT__\"></label>
							<button onclick=\"startSuite('ALL')\">Start All</button>
							<button onclick=\"startSuite('TLS12')\">TLS 1.2</button>
							<button onclick=\"startSuite('TLS13')\">TLS 1.3</button>
							<button onclick=\"startSuite('RFC')\">RFC</button>
							<button onclick=\"startSuite('RANDOM')\">Random</button>
							<a class=\"button-link\" href=\"/api/report\">PDF Report</a>
							<button class=\"stop\" onclick=\"stopTests()\">End Tests</button>
						</section>
						<section class=\"terminal\">
							<table>
								<thead><tr><th>Test</th><th>State</th><th>Progress</th><th>Completed</th><th>Message</th></tr></thead>
								<tbody id=\"statusRows\"></tbody>
							</table>
						</section>
						<section class=\"terminal\">
							<div class=\"note\">log view</div>
							<pre class=\"log-view\" id=\"logRows\"></pre>
						</section>
						<section class=\"terminal\">
							<div class=\"note\">
								<label>RFC Vector Category
									<select id=\"categoryFilter\" onchange=\"renderVectors()\">
										<option value=\"\">all categories</option>
									</select>
								</label>
							</div>
							<div class=\"note\" id=\"vectorNote\">loading vector catalog...</div>
							<table>
								<thead><tr><th>Category</th><th>RFC Vector</th><th>Source</th><th>Bytes</th><th>Description</th></tr></thead>
								<tbody id=\"vectorRows\"></tbody>
							</table>
						</section>
					</main>
					<script>
						let vectorCatalog = { count: 0, categories: [], vectors: [] };
						async function refreshStatus() {
							const response = await fetch('/api/status', { cache: 'no-store' });
							const data = await response.json();
							document.getElementById('tests').textContent = data.tests.length;
							document.getElementById('running').textContent = data.tests.filter(t => t.state === 'RUNNING').length;
							document.getElementById('updated').textContent = new Date(data.generatedAt).toLocaleTimeString();
							if (document.activeElement !== document.getElementById('host')) document.getElementById('host').value = data.host;
							if (document.activeElement !== document.getElementById('port')) document.getElementById('port').value = data.port;
							document.getElementById('logRows').textContent = (data.logs || []).slice(-120).join('\\n');
							document.getElementById('statusRows').innerHTML = data.tests.map(t => `
								<tr>
									<td class=\"matrix-cell\">${t.name}</td>
									<td><span class=\"badge ${t.state}\">${t.state}</span></td>
									<td><progress max=\"100\" value=\"${t.progress}\"></progress> ${t.progress}%</td>
									<td>${t.completed} / ${t.total}</td>
									<td>${t.message || ''}</td>
								</tr>`).join('');
						}
						async function refreshVectors() {
							const response = await fetch('/api/vectors', { cache: 'no-store' });
							vectorCatalog = await response.json();
							document.getElementById('vectors').textContent = vectorCatalog.count;
							const filter = document.getElementById('categoryFilter');
							filter.innerHTML = '<option value=\"\">all categories</option>' + vectorCatalog.categories.map(c =>
								`<option value=\"${c.name}\">${c.name} (${c.count})</option>`).join('');
							renderVectors();
						}
						function renderVectors() {
							const category = document.getElementById('categoryFilter').value;
							const filtered = category ? vectorCatalog.vectors.filter(v => v.category === category) : vectorCatalog.vectors;
							const visible = filtered.slice(0, 700);
							document.getElementById('vectorNote').textContent = `catalog=${vectorCatalog.count} vectors | category=${category || 'all'} | category-count=${filtered.length} | rendered=${visible.length} | full stream available at /api/vectors`;
							document.getElementById('vectorRows').innerHTML = visible.map(v => `
								<tr><td class=\"matrix-cell\">${v.category}</td><td class=\"matrix-cell\">${v.name}</td><td>${v.rfc}</td><td>${v.bytes}</td><td>${v.description}</td></tr>`).join('');
						}
						async function startSuite(suite) {
							const body = new URLSearchParams({
								host: document.getElementById('host').value,
								port: document.getElementById('port').value,
								suite
							});
							await fetch('/api/start', { method: 'POST', body });
							await refreshStatus();
						}
						async function stopTests() {
							await fetch('/api/stop', { method: 'POST' });
							await refreshStatus();
						}
						refreshVectors();
						refreshStatus();
						setInterval(refreshStatus, 1000);
					</script>
				</body>
				</html>
				""".replace("__HOST__", CommonProperties.getInstance().getTlsHost())
				.replace("__PORT__", String.valueOf(CommonProperties.getInstance().getTlsPort()));
	}
}
