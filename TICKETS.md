# TLS Fuzzer Improvement Tickets

These tickets convert the current improvement TODOs into concrete work items. They can be copied into GitHub Issues when repository authentication is available.

## Ticket Index

| ID | Title | Priority | Area | Status |
| --- | --- | --- | --- | --- |
| TLSFZ-001 | Add persistent run IDs | High | Reporting/Dashboard | Open |
| TLSFZ-002 | Persist per-vector execution results | High | Fuzzer Core | Open |
| TLSFZ-003 | Add CSV and JSON report exports | Medium | Reporting | Open |
| TLSFZ-004 | Parse TLS alert responses | High | Protocol Analysis | Open |
| TLSFZ-005 | Add response classification | High | Protocol Analysis | Open |
| TLSFZ-006 | Add RFC category selection | Medium | Dashboard/Fuzzer Core | Open |
| TLSFZ-007 | Add rate limiting and concurrency controls | High | Fuzzer Core | Open |
| TLSFZ-008 | Replace printStackTrace with structured logging | Medium | Code Quality | Open |
| TLSFZ-009 | Add local TLS server integration tests | High | Testing | Open |
| TLSFZ-010 | Separate legacy and modern generators | Medium | Code Quality | Open |
| TLSFZ-011 | Add dashboard run history | Medium | Dashboard | Open |
| TLSFZ-012 | Add report pagination tests | Medium | Reporting/Testing | Open |
| TLSFZ-013 | Make report output directory configurable | Low | Configuration | Open |
| TLSFZ-014 | Add report preview screenshot to README | Low | Documentation | Open |

## TLSFZ-001 Add Persistent Run IDs

Priority: High  
Area: Reporting/Dashboard  
Labels: `enhancement`, `reporting`, `dashboard`

Problem:
Current reports, dashboard state, and logs are not tied to a durable run identifier. After multiple runs, it is difficult to correlate generated PDF files, dashboard rows, and log entries.

Scope:
- Generate a unique run ID when `TLSController.startTests(...)` begins.
- Include the run ID in `FuzzerStatusRegistry` logs and statuses.
- Include the run ID in report filenames and PDF content.
- Expose the run ID through `/api/status`.

Acceptance Criteria:
- Starting any suite creates one stable run ID.
- The run ID is visible in browser dashboard status JSON.
- PDF filename contains the run ID or a run-ID suffix.
- Report body includes the run ID.
- Unit tests cover run ID creation and report inclusion.

## TLSFZ-002 Persist Per-Vector Execution Results

Priority: High  
Area: Fuzzer Core  
Labels: `enhancement`, `fuzzer-core`, `evidence`

Problem:
The current system tracks dashboard job progress but not each vector result. Reports cannot show which exact vector caused a timeout, exception, alert, or response.

Scope:
- Create a result model for vector execution.
- Store vector name, category, RFC source, request size, response size, exception, timing, and response classification.
- Keep storage bounded for very large suites.
- Feed result summaries into reports.

Acceptance Criteria:
- RFC suite records one result per executed vector.
- Random suites record useful generated-case metadata.
- Failed vectors can be listed in report output.
- Storage strategy does not crash the JVM on the 48k RFC suite.

## TLSFZ-003 Add CSV And JSON Report Exports

Priority: Medium  
Area: Reporting  
Labels: `enhancement`, `reporting`, `export`

Problem:
PDF reports are readable, but machine processing needs CSV/JSON.

Scope:
- Add JSON export with run metadata, job summaries, and per-vector results when available.
- Add CSV export for tabular vector/job results.
- Add browser dashboard download links.

Acceptance Criteria:
- `/api/report.json` returns a JSON report for the latest run.
- `/api/report.csv` returns a CSV report for the latest run.
- Files are also written into `reports/`.
- Unit tests verify valid JSON and CSV headers.

## TLSFZ-004 Parse TLS Alert Responses

Priority: High  
Area: Protocol Analysis  
Labels: `enhancement`, `tls`, `analysis`

Problem:
TLS alert responses are currently logged as bytes only. Alert level and description should be decoded.

Scope:
- Detect TLS alert records in responses.
- Parse level and description.
- Map common alert descriptions to names from RFC 5246/RFC 8446.
- Show parsed alerts in dashboard and reports.

Acceptance Criteria:
- Alert responses show `warning` or `fatal`.
- Known alert descriptions show names like `decode_error`, `illegal_parameter`, or `protocol_version`.
- Unknown descriptions remain visible as numeric values.
- Unit tests cover several alert byte arrays.

## TLSFZ-005 Add Response Classification

Priority: High  
Area: Protocol Analysis  
Labels: `enhancement`, `analysis`, `dashboard`

Problem:
Different target behaviors are collapsed into exceptions/log lines. The fuzzer should classify outcomes.

Scope:
- Add response classes such as `SUCCESS_BYTES`, `TLS_ALERT`, `TIMEOUT`, `TCP_RESET`, `CONNECTION_REFUSED`, `CLOSE`, `MALFORMED_RESPONSE`, and `UNEXPECTED_ERROR`.
- Use classifications in statuses, logs, and reports.
- Aggregate counts per suite/category.

Acceptance Criteria:
- Each send attempt produces one classification.
- Dashboard can show aggregate counts.
- PDF report includes classification summary.
- Unit tests cover classification mapping.

## TLSFZ-006 Add RFC Category Selection

Priority: Medium  
Area: Dashboard/Fuzzer Core  
Labels: `enhancement`, `dashboard`, `rfc-suite`

Problem:
The RFC suite currently starts all RFC categories together. Users need targeted category runs.

Scope:
- Add category checkboxes or a multi-select control to the browser dashboard.
- Add equivalent controls or a compact selector to Swing UI.
- Add controller support for selected RFC categories.

Acceptance Criteria:
- User can run only `record-header`.
- User can run multiple selected categories.
- `/api/start` accepts category selection.
- Dashboard displays only jobs for selected categories.

## TLSFZ-007 Add Rate Limiting And Concurrency Controls

Priority: High  
Area: Fuzzer Core  
Labels: `enhancement`, `stability`, `configuration`

Problem:
The fuzzer can overwhelm fragile targets because job concurrency and send rate are coarse.

Scope:
- Add configurable delay between requests.
- Add per-suite or per-category concurrency limits.
- Add dashboard controls for rate and concurrency.
- Include settings in reports.

Acceptance Criteria:
- User can configure requests per second or delay in milliseconds.
- Rate setting affects RFC and random suites.
- Report records rate/concurrency settings.
- Tests cover configuration parsing.

## TLSFZ-008 Replace printStackTrace With Structured Logging

Priority: Medium  
Area: Code Quality  
Labels: `code-quality`, `logging`

Problem:
Several catch blocks still call `printStackTrace()`, which duplicates noisy output and bypasses structured logging.

Scope:
- Replace `printStackTrace()` with logger calls.
- Keep exception stack traces where useful via `logger.log(Level.SEVERE, message, e)`.
- Ensure dashboard log messages remain concise.

Acceptance Criteria:
- `rg "printStackTrace" src` returns no production occurrences.
- Errors still appear in `log/`.
- Tests continue passing.

## TLSFZ-009 Add Local TLS Server Integration Tests

Priority: High  
Area: Testing  
Labels: `testing`, `integration`, `tls`

Problem:
Unit tests validate generation and reporting, but not live client/server behavior.

Scope:
- Add a controlled local TLS test target.
- Run a small suite against it.
- Assert connection behavior and dashboard status updates.

Acceptance Criteria:
- Integration test can run locally without external network.
- Test is bounded and does not run the full 48k suite.
- CI can skip it with a profile if needed.

## TLSFZ-010 Separate Legacy And Modern Generators

Priority: Medium  
Area: Code Quality  
Labels: `refactor`, `generator`

Problem:
Older generator helper classes coexist with the newer `TLSProtocolDataGenerator`, making ownership unclear.

Scope:
- Identify legacy-only classes.
- Mark deprecated wrappers or move legacy examples behind clearer names.
- Keep compatibility where existing code uses them.

Acceptance Criteria:
- Generator package has clear modern vs legacy roles.
- README/AGENT mention the intended generator entry point.
- Tests protect current public behavior.

## TLSFZ-011 Add Dashboard Run History

Priority: Medium  
Area: Dashboard  
Labels: `enhancement`, `dashboard`, `history`

Problem:
Dashboards show the current/latest run only. Users need access to completed run summaries.

Scope:
- Store recent run summaries in memory.
- Add browser dashboard history view.
- Link history entries to report files.

Acceptance Criteria:
- Browser dashboard lists recent runs.
- Each history row shows run ID, target, suite, start/end, and result.
- Report link works for completed runs.

## TLSFZ-012 Add Report Pagination Tests

Priority: Medium  
Area: Reporting/Testing  
Labels: `testing`, `reporting`

Problem:
PDF pagination exists but needs direct test coverage for many jobs/log lines.

Scope:
- Create a report test with enough statuses/logs for multiple pages.
- Verify multiple `/Page` objects.
- Verify logo/footer appear in each page content stream.

Acceptance Criteria:
- Test creates at least two-page report.
- PDF text contains `Page 1 / 2` and `Page 2 / 2`.
- Test passes with current dependency-free PDF writer.

## TLSFZ-013 Make Report Output Directory Configurable

Priority: Low  
Area: Configuration  
Labels: `enhancement`, `configuration`, `reporting`

Problem:
Reports always write to `reports/`.

Scope:
- Add property for report output directory.
- Default to `reports/`.
- Ensure `/api/report` uses configured path.

Acceptance Criteria:
- Property can redirect reports to another folder.
- Default behavior remains unchanged.
- Unit test covers default and custom value.

## TLSFZ-014 Add Report Preview Screenshot To README

Priority: Low  
Area: Documentation  
Labels: `documentation`, `reporting`

Problem:
README documents reports but does not show a preview.

Scope:
- Add a stable report screenshot or sample page image under `pics/`.
- Add README section showing report layout.

Acceptance Criteria:
- README includes the report preview image.
- Image path is committed under `pics/`.
- Screenshot does not expose private target data.
