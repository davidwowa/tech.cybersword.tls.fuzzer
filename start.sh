#!/usr/bin/env bash
set -euo pipefail

MAVEN_BIN="${MAVEN_BIN:-/home/david/progs/apache-maven-3.9.11/bin/mvn}"
JAR_PATH="target/tech.cybersword.tls.fuzzer-0.0.1-SNAPSHOT.jar"
TLS_PORT="${TLS_PORT:-31337}"
LOG_DIR="${LOG_DIR:-log}"
START_LOCAL_SERVER=false
SKIP_BUILD=false

usage() {
  cat <<'USAGE'
Usage: ./start.sh [options]

Options:
  --with-local-server   Start an OpenSSL TLS server on localhost:31337 before the fuzzer.
  --skip-build          Start the existing jar without running Maven package.
  --help                Show this help.

Environment:
  MAVEN_BIN=/path/to/mvn   Maven executable to use.
  TLS_PORT=31337           Local OpenSSL server port when --with-local-server is used.
  LOG_DIR=log              Directory for generated logs.

Dashboard:
  http://localhost:8080/
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-local-server)
      START_LOCAL_SERVER=true
      ;;
    --skip-build)
      SKIP_BUILD=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

mkdir -p "$LOG_DIR"

if [[ "$SKIP_BUILD" == "false" ]]; then
  "$MAVEN_BIN" package
fi

if [[ ! -f "$JAR_PATH" ]]; then
  echo "Missing jar: $JAR_PATH" >&2
  echo "Run without --skip-build or build the project first." >&2
  exit 1
fi

if [[ "$START_LOCAL_SERVER" == "true" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required for --with-local-server" >&2
    exit 1
  fi

  if ss -ltn "sport = :$TLS_PORT" | grep -q LISTEN; then
    echo "Local TLS server port $TLS_PORT is already in use; not starting OpenSSL."
  else
    openssl req -x509 -newkey rsa:2048 \
      -keyout /tmp/tls-fuzzer-key.pem \
      -out /tmp/tls-fuzzer-cert.pem \
      -days 1 \
      -nodes \
      -subj /CN=localhost >"$LOG_DIR/tls-fuzzer-cert-generation.log" 2>&1

    openssl s_server \
      -key /tmp/tls-fuzzer-key.pem \
      -cert /tmp/tls-fuzzer-cert.pem \
      -accept "$TLS_PORT" \
      -www \
      -debug >"$LOG_DIR/tls-fuzzer-openssl-server.log" 2>&1 &

    OPENSSL_PID="$!"
    echo "Started local OpenSSL TLS server on localhost:$TLS_PORT (PID $OPENSSL_PID)."
    echo "OpenSSL log: $LOG_DIR/tls-fuzzer-openssl-server.log"
  fi
fi

echo "Starting TLS fuzzer dashboard: http://localhost:8080/"
exec java -jar "$JAR_PATH"
