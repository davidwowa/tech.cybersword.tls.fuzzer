# TLS Fuzzer Agent Notes

## Project Goal

This project is a Java 17 TLS fuzzer for TLS 1.2 and TLS 1.3. It generates byte-level TLS records, malformed headers, RFC enum probes, boundary vectors, and randomized payloads, sends them to a configured TLS target, and exposes the run through browser and Swing dashboards.

The current runtime starts idle: launching the jar opens dashboards only. A fuzzing run begins when a user clicks `Start All`, `TLS 1.2`, `TLS 1.3`, `RFC`, or `Random`.

## Current Runtime Defaults

Configuration lives in `tech.cybersword.tls.fuzzer.properties`.

- Target host: `localhost`
- Target port: `31337`
- Requests per random/legacy job: `100`
- Worker threads: `4`
- Socket timeout: `100` ms
- Random fixed-array size: `1000`
- Random variable-array range: `0..10000`
- Browser dashboard: enabled
- Browser dashboard URL: `http://localhost:8080/`
- Browser dashboard HTTPS: disabled by default
- Logs directory: `log/`
- Reports directory: `reports/`

`start.sh --with-local-server` starts an OpenSSL `s_server` on `localhost:31337` and writes helper logs into `log/`.

## Build And Test

Preferred Maven path used in this workspace:

```bash
/home/david/progs/apache-maven-3.9.11/bin/mvn test
/home/david/progs/apache-maven-3.9.11/bin/mvn package
java -jar target/tech.cybersword.tls.fuzzer-1.0.0-SNAPSHOT.jar
```

Project layout is non-standard: production source root is `src`, while tests live in `src/test/java`. `pom.xml` excludes `src/test/**` from main compilation and configures JUnit 5 through Surefire.

## Project Structure

- `src/tech/cybersword/tls/fuzzer/controller/`
  - `TLSController.java`: main entry point, dashboard startup, suite selection, job orchestration, stop handling, report trigger.
- `src/tech/cybersword/tls/fuzzer/client/`
  - `TLSClient.java`: raw TCP socket sender/receiver for generated TLS byte arrays.
- `src/tech/cybersword/tls/fuzzer/generator/`
  - `TLSProtocolDataGenerator.java`: main RFC/vector generator.
  - `TLSFuzzVector.java`: immutable vector model with name, category, RFC source, description, and byte payload.
  - `TLS12TestDataGenerator.java`: TLS 1.2 compatibility wrapper and older examples.
  - `TLS13TestDataGenerator.java`: TLS 1.3 compatibility wrapper and older examples.
  - `TLS13TestValidDataGenerator.java`: older TLS 1.3 generator copy.
  - `TLSExtensionDataGenerator.java`: older extension fixture/random data helpers.
- `src/tech/cybersword/tls/fuzzer/dashboard/`
  - `BrowserDashboardServer.java`: built-in HTTP/optional HTTPS browser dashboard and REST-ish endpoints.
  - `FuzzerStatusRegistry.java`: concurrent in-memory status/log registry.
  - `FuzzerTestStatus.java`: immutable status snapshot model.
  - `TLSReportCreator.java`: dependency-free PDF report generator with logo header and footer URL.
- `src/tech/cybersword/tls/fuzzer/ui/`
  - `TLSSystemTray.java`: AWT tray integration when supported.
  - `TLSDashboard.java`: terminal-style Swing dashboard; no-op in headless environments.
- `src/tech/cybersword/tls/fuzzer/common/`
  - `CommonProperties.java`: properties loader.
- `src/tech/cybersword/tls/fuzzer/util/`
  - Logging, random, array, hex, and property helpers.
- `src/test/java/tech/cybersword/tls/fuzzer/`
  - JUnit tests for vector generation, dashboard state, logging, and reports.
- `pics/`
  - README/dashboard images and `TLSFuzzerLogo.png`.
- `log/`
  - Runtime logs. Ignored by git.
- `reports/`
  - Generated PDF reports. Ignored by git.

## Dashboard And APIs

Browser dashboard:

- URL: `http://localhost:8080/`
- Style: terminal/matrix-like dark UI.
- `/api/status`: current run state, target, suite, job status rows, and dashboard logs.
- `/api/vectors`: full RFC vector catalog with categories and descriptions.
- `/api/report`: downloads the latest PDF report or creates a snapshot report on demand.
- `/api/health`: health check JSON.

HTTPS dashboard mode requires:

```properties
dashboard.browser.https.enabled=true
dashboard.browser.https.keystore=/path/to/dashboard.jks
dashboard.browser.https.keystorePassword=changeit
```

Swing dashboard mirrors browser controls: target host/port, suite buttons, stop button, status table, and live log view.

## Current Fuzzer Coverage

The RFC byte-stream suite is generated from RFC 5246 and RFC 8446 structures plus illustrated examples from:

- `https://tls12.xargs.org/#open-all`
- `https://tls13.xargs.org/#open-all`
- `https://www.rfc-editor.org/rfc/rfc5246.txt`
- `https://www.rfc-editor.org/rfc/rfc8446.txt`

Current RFC catalog size: `48561` vectors.

Categories:

- `client-hello`
- `xargs`
- `record-header`
- `handshake-header`
- `alert-header`
- `content-type`
- `protocol-version`
- `handshake-type`
- `alert-description`
- `cipher-suite`
- `named-group`
- `signature-scheme`
- `extension-type`
- `malformed-length`

Fully enumerating every possible TLS byte stream is impossible because TLS includes variable-length opaque fields up to 2^16 and 2^24 bytes. The current approach focuses on high-value parser surfaces: all one-byte header selectors, RFC enum values, compatibility fields, random payloads, and length boundaries.

## Reporting

`TLSReportCreator` creates dependency-free PDF 1.4 reports in `reports/`.

Report behavior:

- Automatic report generation after a run ends in `TLSController.waitForFuzzerJobs`.
- Manual report download through `/api/report`.
- Latest report path is held in memory by `TLSReportCreator`.
- Report includes `pics/TLSFuzzerLogo.png` in the header on each page.
- Report footer includes clickable `https://cybersword.tech` on each page.
- Report body includes target, suite/start mode, start/end time, total/completed tests, failed jobs, RFC 5246/RFC 8446 links, job summary, recent logs, and conclusion.

Implementation notes:

- The PDF writer embeds the logo as a Flate-compressed `/Image` XObject.
- It uses built-in JDK APIs only: `ImageIO`, `DeflaterOutputStream`, and manual PDF object writing.
- Tests inspect report content with ISO-8859-1 because generated PDFs contain binary image streams.

## Tests

Current tests:

- `FuzzerStatusRegistryTest`
- `TLSReportCreatorTest`
- `LoggerUtilTest`
- `TLSProtocolDataGeneratorTest`
- `TLSRfcByteStreamVectorTest`

Last known passing verification:

```bash
/home/david/progs/apache-maven-3.9.11/bin/mvn test
/home/david/progs/apache-maven-3.9.11/bin/mvn package
```

Expected result at last update: 11 tests passing.

## Operational Notes

- The fuzzer starts idle; click a dashboard suite button to begin.
- Runtime logs are written under `log/`.
- Generated reports are written under `reports/`.
- `mvn package` regenerates root SBOM JSON/XML files.
- Running against a closed target port produces many `Connection refused` messages. Start a TLS target first or change `tls.host` / `tls.port`.
- `/api/vectors` is large. The browser page renders a bounded visible slice and lets the user filter categories.
- `reports/` and `log/` are ignored by git.
- Preserve existing dirty work unless explicitly asked to revert it.

## Improvement TODOs

Detailed ticket drafts are available in `TICKETS.md`.

- Add persistent run IDs so reports, logs, and dashboard statuses can be tied to one execution.
- Save full per-vector results, not only job progress, for better analysis after long runs.
- Add CSV/JSON report exports next to PDF.
- Add response classification: timeout, TCP reset, close_notify, TLS alert, malformed response, unexpected data.
- Parse returned TLS alerts and include alert level/description in reports.
- Add configurable RFC category selection instead of running all RFC categories at once.
- Add rate limiting and per-suite concurrency controls to avoid overwhelming fragile targets.
- Replace repeated `e.printStackTrace()` calls with structured logger-only handling.
- Add integration tests with a controlled local TLS server.
- Split old generator helpers from the modern `TLSProtocolDataGenerator` or mark deprecated classes clearly.
- Add a real dashboard history view for completed runs.
- Add report pagination tests with many statuses/log entries.
- Add screenshots or generated report preview to README once the report layout stabilizes.
