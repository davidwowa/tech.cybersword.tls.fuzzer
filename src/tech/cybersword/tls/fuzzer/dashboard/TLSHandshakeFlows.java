package tech.cybersword.tls.fuzzer.dashboard;

import java.util.List;

public final class TLSHandshakeFlows {

	private static final String CLIENT = "#67e8f9";
	private static final String SERVER = "#f59e0b";
	private static final String CRYPTO = "#c084fc";
	private static final String RECORD = "#22c55e";
	private static final String APPLICATION = "#d9ff5f";
	private static final String TLS12 = "#38bdf8";
	private static final String TLS13 = "#fb7185";

	private static final List<TLSHandshakeStep> TLS13_STEPS = List.of(
			step13(1, "client", "key schedule", "Client key exchange generation",
					"Generate the client ephemeral key share used by the TLS 1.3 key schedule.", CRYPTO, false),
			step13(2, "client", "handshake", "ClientHello",
					"Send the TLS 1.3 ClientHello with supported_versions, key_share, signature_algorithms, SNI, and extension probes.",
					CLIENT, true),
			step13(3, "server", "key schedule", "Server key exchange generation",
					"Server selects parameters and generates its ephemeral key share.", CRYPTO, false),
			step13(4, "server", "handshake", "ServerHello",
					"ServerHello selects protocol version, cipher suite, and key share.", SERVER, false),
			step13(5, "server", "key schedule", "Server handshake traffic keys calculation",
					"Derive server handshake traffic secrets and record protection keys.", CRYPTO, false),
			step13(6, "client", "key schedule", "Client handshake traffic keys calculation",
					"Derive client handshake traffic secrets and record protection keys.", CRYPTO, false),
			step13(7, "server", "compatibility", "Server ChangeCipherSpec",
					"Optional compatibility ChangeCipherSpec record seen in some TLS 1.3 handshakes.", RECORD, false),
			step13(8, "shared", "record protection", "Wrapped record",
					"Encrypted TLSCiphertext wrapper carrying the next handshake message.", RECORD, false),
			step13(9, "server", "handshake", "EncryptedExtensions",
					"Server encrypted extensions sent after ServerHello.", SERVER, false),
			step13(10, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for the certificate flight.", RECORD, false),
			step13(11, "server", "authentication", "Certificate",
					"Server certificate chain message.", SERVER, false),
			step13(12, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for CertificateVerify.", RECORD, false),
			step13(13, "server", "authentication", "CertificateVerify",
					"Server signs the transcript to prove certificate private-key possession.", SERVER, false),
			step13(14, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for the server Finished message.", RECORD, false),
			step13(15, "server", "handshake", "Server Finished",
					"Server verifies the handshake transcript with its Finished MAC.", SERVER, false),
			step13(16, "server", "key schedule", "Server application traffic keys calculation",
					"Derive server application traffic secrets and record protection keys.", CRYPTO, false),
			step13(17, "client", "key schedule", "Client application traffic keys calculation",
					"Derive client application traffic secrets and record protection keys.", CRYPTO, false),
			step13(18, "client", "compatibility", "Client ChangeCipherSpec",
					"Optional client compatibility ChangeCipherSpec record.", RECORD, false),
			step13(19, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for the client Finished message.", RECORD, false),
			step13(20, "client", "handshake", "Client Finished",
					"Client verifies the handshake transcript with its Finished MAC.", CLIENT, false),
			step13(21, "shared", "record protection", "Wrapped record",
					"Encrypted application-data record wrapper.", RECORD, false),
			step13(22, "client", "application", "Client application data",
					"First protected application payload sent by the client.", APPLICATION, false),
			step13(23, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for post-handshake data.", RECORD, false),
			step13(24, "server", "post-handshake", "NewSessionTicket 1",
					"First TLS 1.3 post-handshake session ticket.", SERVER, false),
			step13(25, "shared", "record protection", "Wrapped record",
					"Encrypted record boundary for another post-handshake ticket.", RECORD, false),
			step13(26, "server", "post-handshake", "NewSessionTicket 2",
					"Second TLS 1.3 post-handshake session ticket.", SERVER, false),
			step13(27, "shared", "record protection", "Wrapped record",
					"Final encrypted record wrapper observed in the modeled TLS 1.3 flow.", RECORD, false));

	private static final List<TLSHandshakeStep> TLS12_STEPS = List.of(
			step12(1, "client", "handshake", "ClientHello",
					"Send the TLS 1.2 ClientHello with legacy_version, random, cipher suites, compression methods, and extensions.",
					CLIENT, true),
			step12(2, "server", "handshake", "ServerHello",
					"Server selects protocol version, random, session, cipher suite, and compression method.", SERVER, false),
			step12(3, "server", "authentication", "Certificate",
					"Server certificate chain message.", SERVER, false),
			step12(4, "server", "key exchange", "Server key exchange generation",
					"Generate ephemeral key exchange parameters for suites that require ServerKeyExchange.", CRYPTO, false),
			step12(5, "server", "key exchange", "ServerKeyExchange",
					"Send server key exchange parameters and signature where required.", SERVER, false),
			step12(6, "server", "handshake", "ServerHelloDone",
					"Server marks the end of its cleartext handshake flight.", SERVER, false),
			step12(7, "client", "key exchange", "Client key exchange generation",
					"Generate pre-master secret or ephemeral client key exchange parameters.", CRYPTO, false),
			step12(8, "client", "key exchange", "ClientKeyExchange",
					"Send the TLS 1.2 ClientKeyExchange message.", CLIENT, false),
			step12(9, "client", "key schedule", "Client encryption keys calculation",
					"Derive client write keys, IVs, and MAC keys from the TLS 1.2 master secret.", CRYPTO, false),
			step12(10, "client", "record protection", "Client ChangeCipherSpec",
					"Client switches to negotiated record protection.", RECORD, false),
			step12(11, "client", "handshake", "Client Finished",
					"Client sends Finished under the negotiated record protection.", CLIENT, false),
			step12(12, "server", "key schedule", "Server encryption keys calculation",
					"Derive server write keys, IVs, and MAC keys from the TLS 1.2 master secret.", CRYPTO, false),
			step12(13, "server", "record protection", "Server ChangeCipherSpec",
					"Server switches to negotiated record protection.", RECORD, false),
			step12(14, "server", "handshake", "Server Finished",
					"Server sends Finished under the negotiated record protection.", SERVER, false),
			step12(15, "client", "application", "Client application data",
					"First protected application payload sent by the client.", APPLICATION, false),
			step12(16, "server", "application", "Server application data",
					"Protected application payload returned by the server.", APPLICATION, false),
			step12(17, "client", "alert", "Client close_notify",
					"Client closes the TLS session with a close_notify alert.", CLIENT, false));

	private TLSHandshakeFlows() {
	}

	public static List<TLSHandshakeStep> tls13() {
		return TLS13_STEPS;
	}

	public static List<TLSHandshakeStep> tls12() {
		return TLS12_STEPS;
	}

	public static List<TLSHandshakeStep> all() {
		return java.util.stream.Stream.concat(TLS13_STEPS.stream(), TLS12_STEPS.stream()).toList();
	}

	public static TLSHandshakeStep tls13ClientHello() {
		return TLS13_STEPS.get(1);
	}

	public static TLSHandshakeStep tls12ClientHello() {
		return TLS12_STEPS.get(0);
	}

	public static String protocolColor(String protocol) {
		return "TLS 1.2".equals(protocol) ? TLS12 : TLS13;
	}

	private static TLSHandshakeStep step13(int sequence, String actor, String category, String title, String description,
			String color, boolean implemented) {
		return new TLSHandshakeStep("TLS 1.3", sequence, actor, category, title, description, color, implemented);
	}

	private static TLSHandshakeStep step12(int sequence, String actor, String category, String title, String description,
			String color, boolean implemented) {
		return new TLSHandshakeStep("TLS 1.2", sequence, actor, category, title, description, color, implemented);
	}
}
