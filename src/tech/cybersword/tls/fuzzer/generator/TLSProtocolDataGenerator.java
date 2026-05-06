package tech.cybersword.tls.fuzzer.generator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tech.cybersword.tls.fuzzer.util.ArrayUtils;
import tech.cybersword.tls.fuzzer.util.RandomUtil;

public class TLSProtocolDataGenerator {

	private static final int[] TLS_RECORD_CONTENT_TYPES = { 20, 21, 22, 23 };
	private static final int[] TLS_RECORD_CONTENT_TYPE_BOUNDARIES = { 0, 19, 24, 255 };
	private static final int[] TLS_PROTOCOL_VERSIONS = { 0x0000, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x7f17,
			0xffff };
	private static final int[] TLS_RECORD_LENGTH_PROBES = { 0, 1, 2, 4, 5, 7, 16, 31, 49, 88, 122, 165, 248, 255,
			512, 1024, 4096, 16383, 16384, 16385, 32768, 65535 };
	private static final int[] TLS_HANDSHAKE_LENGTH_PROBES = { 0, 1, 4, 32, 45, 161, 212, 811, 65535, 16777215 };
	private static final int[] TLS12_HANDSHAKE_TYPES = { 0, 1, 2, 11, 12, 13, 14, 15, 16, 20, 255 };
	private static final int[] TLS13_HANDSHAKE_TYPES = { 1, 2, 4, 5, 8, 11, 13, 15, 20, 24, 254, 255 };
	private static final int[] TLS_ALERT_DESCRIPTIONS = { 0, 10, 20, 21, 22, 30, 40, 41, 42, 43, 44, 45, 46, 47, 48,
			49, 50, 51, 60, 70, 71, 80, 86, 90, 100, 109, 110, 111, 112, 113, 114, 115, 116, 120, 255 };
	private static final int[] TLS12_CIPHER_SUITES = { 0x0000, 0x000a, 0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d,
			0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0x00ff };
	private static final int[] TLS13_CIPHER_SUITES = { 0x1301, 0x1302, 0x1303, 0x1304, 0x1305, 0x00ff };
	private static final int[] TLS13_NAMED_GROUPS = { 0x0017, 0x0018, 0x0019, 0x001d, 0x001e, 0x0100, 0x0101, 0x0102,
			0x0103, 0x0104, 0x01fc, 0x01fd, 0x01fe, 0x01ff, 0x0200, 0x0201 };
	private static final int[] TLS_SIGNATURE_SCHEMES = { 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804,
			0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b };
	private static final int[] TLS_EXTENSION_TYPES = { 0, 1, 5, 10, 13, 14, 15, 16, 18, 19, 20, 21, 35, 41, 42, 43,
			44, 45, 47, 48, 49, 50, 51, 65281, 65535 };

	public enum TLSVersion {
		TLS_1_2(new byte[] { 0x03, 0x03 }),
		TLS_1_3(new byte[] { 0x03, 0x04 });

		private final byte[] wireVersion;

		TLSVersion(byte[] wireVersion) {
			this.wireVersion = wireVersion;
		}

		public byte[] wireVersion() {
			return wireVersion.clone();
		}
	}

	private static TLSProtocolDataGenerator instance;

	private final ArrayUtils arrayUtils = new ArrayUtils();

	private TLSProtocolDataGenerator() {
	}

	public static TLSProtocolDataGenerator getInstance() {
		if (instance == null) {
			instance = new TLSProtocolDataGenerator();
		}
		return instance;
	}

	public byte[] createTLS12ClientHello() {
		return createClientHello(TLSVersion.TLS_1_2, "example.ulfheim.net", false);
	}

	public byte[] createTLS13ClientHello() {
		return createClientHello(TLSVersion.TLS_1_3, "example.ulfheim.net", false);
	}

	public byte[] createTLS12ClientHelloWithRandomExtensions() {
		return createClientHello(TLSVersion.TLS_1_2, "example.ulfheim.net", true);
	}

	public byte[] createTLS13ClientHelloWithRandomExtensions() {
		return createClientHello(TLSVersion.TLS_1_3, "example.ulfheim.net", true);
	}

	public List<TLSFuzzVector> createRfcByteStreamVectors() {
		List<TLSFuzzVector> vectors = new ArrayList<>();
		vectors.add(vector("client-hello", "rfc5246-client-hello", "RFC 5246 A.4.1",
				"TLS 1.2 ClientHello with RFC 5246 TLSPlaintext and Handshake headers", createTLS12ClientHello()));
		vectors.add(vector("client-hello", "rfc8446-client-hello", "RFC 8446 B.3.1",
				"TLS 1.3 ClientHello with supported_versions, psk_key_exchange_modes and key_share",
				createTLS13ClientHello()));
		vectors.add(vector("client-hello", "rfc5246-client-hello-random-extension", "RFC 5246 A.4.1",
				"TLS 1.2 ClientHello with randomized server_name data", createTLS12ClientHelloWithRandomExtensions()));
		vectors.add(vector("client-hello", "rfc8446-client-hello-random-extension", "RFC 8446 B.3.1",
				"TLS 1.3 ClientHello with randomized server_name and key_share data",
				createTLS13ClientHelloWithRandomExtensions()));
		addIllustratedXargsVectors(vectors);
		addAllRecordHeaderVectors(vectors);
		addAllHandshakeHeaderVectors(vectors);
		addAllAlertHeaderVectors(vectors);
		addContentTypeVectors(vectors);
		addProtocolVersionVectors(vectors);
		addHandshakeTypeVectors(vectors);
		addAlertVectors(vectors);
		addCipherSuiteVectors(vectors);
		addNamedGroupVectors(vectors);
		addSignatureSchemeVectors(vectors);
		addExtensionTypeVectors(vectors);
		addMalformedLengthVectors(vectors);
		return List.copyOf(vectors);
	}

	public Map<String, List<TLSFuzzVector>> createRfcByteStreamVectorsByCategory() {
		Map<String, List<TLSFuzzVector>> categorizedVectors = new LinkedHashMap<>();
		for (TLSFuzzVector vector : createRfcByteStreamVectors()) {
			categorizedVectors.computeIfAbsent(vector.getCategory(), category -> new ArrayList<>()).add(vector);
		}
		Map<String, List<TLSFuzzVector>> immutableCategories = new LinkedHashMap<>();
		for (Map.Entry<String, List<TLSFuzzVector>> entry : categorizedVectors.entrySet()) {
			immutableCategories.put(entry.getKey(), List.copyOf(entry.getValue()));
		}
		return Collections.unmodifiableMap(immutableCategories);
	}

	public byte[] createClientHello(TLSVersion tlsVersion, String serverName, boolean fuzzExtensionData) {
		byte[] body = createClientHelloBody(tlsVersion, serverName, fuzzExtensionData);
		byte[] handshake = arrayUtils.appendAllArrays(new byte[] { 0x01 }, uint24(body.length), body);
		return arrayUtils.appendAllArrays(new byte[] { 0x16, 0x03, 0x01 }, uint16(handshake.length), handshake);
	}

	public String describeClientHelloTransferData() {
		return "TLS ClientHello transfers a TLS record header, handshake header, legacy version, client random, "
				+ "session id, cipher suites, compression methods, and extensions. TLS 1.2 negotiates with "
				+ "legacy_version 03 03 and TLS 1.3 advertises 03 04 in supported_versions while keeping the "
				+ "record legacy version 03 01 for compatibility.";
	}

	private byte[] createClientHelloBody(TLSVersion tlsVersion, String serverName, boolean fuzzExtensionData) {
		byte[] random = RandomUtil.getInstance().generateRandomArray(32);
		byte[] sessionId = tlsVersion == TLSVersion.TLS_1_3 ? randomVector(32) : vector8(new byte[0]);
		byte[] cipherSuites = tlsVersion == TLSVersion.TLS_1_3 ? vector16(hex(0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff))
				: vector16(hex(0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35));
		byte[] compressionMethods = vector8(new byte[] { 0x00 });
		byte[] extensions = createExtensions(tlsVersion, serverName, fuzzExtensionData);

		return arrayUtils.appendAllArrays(new byte[] { 0x03, 0x03 }, random, sessionId, cipherSuites,
				compressionMethods, vector16(extensions));
	}

	private byte[] createClientHelloWithCipherSuite(TLSVersion tlsVersion, int cipherSuite) {
		return createClientHelloWithParts(tlsVersion, uint16(cipherSuite), createExtensions(tlsVersion,
				"example.ulfheim.net", false));
	}

	private byte[] createClientHelloWithNamedGroup(int namedGroup) {
		byte[] keyShare = extension(0x0033, vector16(arrayUtils.appendAllArrays(uint16(namedGroup),
				vector16(RandomUtil.getInstance().generateRandomArray(32)))));
		byte[] extensions = arrayUtils.appendAllArrays(extension(0x002b, vector8(hex(0x03, 0x04, 0x03, 0x03))),
				extension(0x002d, vector8(hex(0x01))), keyShare);
		return createClientHelloWithParts(TLSVersion.TLS_1_3, hex(0x13, 0x02), extensions);
	}

	private byte[] createClientHelloWithSignatureScheme(TLSVersion tlsVersion, int signatureScheme) {
		byte[] extensions = arrayUtils.appendAllArrays(extension(0x000d, vector16(uint16(signatureScheme))),
				tlsVersion == TLSVersion.TLS_1_3 ? extension(0x002b, vector8(hex(0x03, 0x04, 0x03, 0x03)))
						: extension(0x0017, new byte[0]));
		return createClientHelloWithParts(tlsVersion,
				tlsVersion == TLSVersion.TLS_1_3 ? hex(0x13, 0x02) : hex(0xc0, 0x2f), extensions);
	}

	private byte[] createClientHelloWithExtension(TLSVersion tlsVersion, int extensionType) {
		byte[] extensions = extension(extensionType, RandomUtil.getInstance().generateRandomArray(4));
		return createClientHelloWithParts(tlsVersion,
				tlsVersion == TLSVersion.TLS_1_3 ? hex(0x13, 0x02) : hex(0xc0, 0x2f), extensions);
	}

	private byte[] createClientHelloWithParts(TLSVersion tlsVersion, byte[] cipherSuites, byte[] extensions) {
		byte[] random = RandomUtil.getInstance().generateRandomArray(32);
		byte[] sessionId = tlsVersion == TLSVersion.TLS_1_3 ? randomVector(32) : vector8(new byte[0]);
		byte[] body = arrayUtils.appendAllArrays(new byte[] { 0x03, 0x03 }, random, sessionId, vector16(cipherSuites),
				vector8(new byte[] { 0x00 }), vector16(extensions));
		byte[] handshake = arrayUtils.appendAllArrays(new byte[] { 0x01 }, uint24(body.length), body);
		return tlsPlaintext(22, 0x0301, handshake);
	}

	private byte[] createExtensions(TLSVersion tlsVersion, String serverName, boolean fuzzExtensionData) {
		byte[] serverNameExtension = extension(0x0000, createServerNameData(serverName, fuzzExtensionData));
		byte[] supportedGroups = extension(0x000a,
				vector16(hex(0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18)));
		byte[] signatureAlgorithms = extension(0x000d,
				vector16(hex(0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a,
						0x08, 0x0b, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01)));

		if (tlsVersion == TLSVersion.TLS_1_2) {
			return arrayUtils.appendAllArrays(serverNameExtension, extension(0x000b, vector8(hex(0x00))),
					supportedGroups, signatureAlgorithms, extension(0x0016, new byte[0]), extension(0x0017, new byte[0]));
		}

		byte[] supportedVersions = extension(0x002b, vector8(hex(0x03, 0x04, 0x03, 0x03)));
		byte[] pskModes = extension(0x002d, vector8(hex(0x01)));
		byte[] keyShare = extension(0x0033, vector16(arrayUtils.appendAllArrays(hex(0x00, 0x1d), vector16(
				fuzzExtensionData ? RandomUtil.getInstance().generateRandomArray(32)
						: hex(0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
								0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2,
								0xcd, 0x16, 0x62, 0x54)))));
		return arrayUtils.appendAllArrays(serverNameExtension, supportedGroups, signatureAlgorithms, supportedVersions,
				pskModes, keyShare);
	}

	private byte[] createServerNameData(String serverName, boolean fuzzExtensionData) {
		byte[] name = fuzzExtensionData ? RandomUtil.getInstance().generateRandomArray(Math.max(1, serverName.length()))
				: serverName.getBytes(StandardCharsets.US_ASCII);
		byte[] hostName = arrayUtils.appendAllArrays(new byte[] { 0x00 }, uint16(name.length), name);
		return vector16(hostName);
	}

	private byte[] extension(int type, byte[] data) {
		return arrayUtils.appendAllArrays(uint16(type), uint16(data.length), data);
	}

	private void addContentTypeVectors(List<TLSFuzzVector> vectors) {
		for (int contentType : TLS_RECORD_CONTENT_TYPES) {
			vectors.add(vector("content-type", "rfc-record-content-type-" + contentType, "RFC 5246 A.1 / RFC 8446 B.1",
					"TLSPlaintext record with content type " + contentType, tlsPlaintext(contentType, 0x0303, new byte[0])));
		}
		for (int contentType : TLS_RECORD_CONTENT_TYPE_BOUNDARIES) {
			vectors.add(vector("content-type", "boundary-record-content-type-" + contentType, "RFC 5246 A.1 / RFC 8446 B.1",
					"Boundary TLSPlaintext content type " + contentType, tlsPlaintext(contentType, 0x0303, new byte[0])));
		}
	}

	private void addIllustratedXargsVectors(List<TLSFuzzVector> vectors) {
		vectors.add(vector("xargs", "xargs-tls12-client-hello", "tls12.xargs.org / RFC 5246 A.4.1",
				"Illustrated TLS 1.2 ClientHello record with server_name, status_request, supported_groups, ec_point_formats, signature_algorithms, renegotiation_info and SCT extensions",
				TLS12TestDataGenerator.getInstance().createTestTLSHello()));
		vectors.add(vector("xargs", "xargs-tls13-client-hello", "tls13.xargs.org / RFC 8446 B.3.1",
				"Illustrated TLS 1.3 ClientHello record with supported_versions, psk_key_exchange_modes and x25519 key_share",
				TLS13TestDataGenerator.getInstance().createTestTLSHello()));
		vectors.add(vector("xargs", "xargs-tls12-server-hello-header", "tls12.xargs.org / RFC 5246 A.4.1",
				"Illustrated TLS 1.2 ServerHello header/body skeleton using record header 16 03 03 00 31 and handshake header 02 00 00 2d",
				tlsPlaintext(22, 0x0303, arrayUtils.appendAllArrays(hex(0x02), uint24(45), new byte[45]))));
		vectors.add(vector("xargs", "xargs-tls13-server-hello-header", "tls13.xargs.org / RFC 8446 B.3.1",
				"Illustrated TLS 1.3 ServerHello header/body skeleton with supported_versions and key_share extension shape",
				tlsPlaintext(22, 0x0303, arrayUtils.appendAllArrays(hex(0x02), uint24(122), new byte[122]))));
	}

	private void addAllRecordHeaderVectors(List<TLSFuzzVector> vectors) {
		for (int contentType = 0; contentType <= 255; contentType++) {
			for (int version : TLS_PROTOCOL_VERSIONS) {
				for (int length : TLS_RECORD_LENGTH_PROBES) {
					vectors.add(vector("record-header",
							"all-record-header-ct" + contentType + "-v" + hexName(version) + "-l" + length,
							"RFC 5246 A.1 / RFC 8446 B.1",
							"TLSPlaintext 5-byte header probe: content_type=" + contentType + ", version=0x"
									+ hexName(version) + ", length=" + length,
							recordHeader(contentType, version, length)));
				}
			}
		}
	}

	private void addAllHandshakeHeaderVectors(List<TLSFuzzVector> vectors) {
		for (int handshakeType = 0; handshakeType <= 255; handshakeType++) {
			for (int length : TLS_HANDSHAKE_LENGTH_PROBES) {
				vectors.add(vector("handshake-header", "all-handshake-header-type" + handshakeType + "-l" + length,
						"RFC 5246 A.4 / RFC 8446 B.3",
						"Handshake header probe: msg_type=" + handshakeType + ", uint24 length=" + length,
						tlsPlaintext(22, 0x0303,
								arrayUtils.appendAllArrays(new byte[] { (byte) handshakeType }, uint24(length)))));
			}
		}
	}

	private void addAllAlertHeaderVectors(List<TLSFuzzVector> vectors) {
		for (int level = 0; level <= 2; level++) {
			for (int description = 0; description <= 255; description++) {
				vectors.add(vector("alert-header", "all-alert-level" + level + "-description" + description,
						"RFC 5246 A.3 / RFC 8446 B.2",
						"Alert record probe: level=" + level + ", description=" + description,
						tlsPlaintext(21, 0x0303, new byte[] { (byte) level, (byte) description })));
			}
		}
	}

	private void addProtocolVersionVectors(List<TLSFuzzVector> vectors) {
		for (int version : TLS_PROTOCOL_VERSIONS) {
			vectors.add(vector("protocol-version", "rfc-record-version-" + hexName(version), "RFC 5246 A.1 / RFC 8446 B.1",
					"TLSPlaintext record using protocol version 0x" + hexName(version),
					tlsPlaintext(22, version, new byte[] { 0x00, 0x00, 0x00, 0x00 })));
		}
	}

	private void addHandshakeTypeVectors(List<TLSFuzzVector> vectors) {
		for (int handshakeType : TLS12_HANDSHAKE_TYPES) {
			vectors.add(vector("handshake-type", "rfc5246-handshake-type-" + handshakeType, "RFC 5246 A.4",
					"TLS 1.2 Handshake message type " + handshakeType, handshakeRecord(handshakeType, 0x0303, new byte[0])));
		}
		for (int handshakeType : TLS13_HANDSHAKE_TYPES) {
			vectors.add(vector("handshake-type", "rfc8446-handshake-type-" + handshakeType, "RFC 8446 B.3",
					"TLS 1.3 Handshake message type " + handshakeType, handshakeRecord(handshakeType, 0x0303, new byte[0])));
		}
	}

	private void addAlertVectors(List<TLSFuzzVector> vectors) {
		for (int alertDescription : TLS_ALERT_DESCRIPTIONS) {
			vectors.add(vector("alert-description", "rfc-alert-fatal-" + alertDescription, "RFC 5246 A.3 / RFC 8446 B.2",
					"Fatal alert description " + alertDescription,
					tlsPlaintext(21, 0x0303, new byte[] { 0x02, (byte) alertDescription })));
		}
	}

	private void addCipherSuiteVectors(List<TLSFuzzVector> vectors) {
		for (int cipherSuite : TLS12_CIPHER_SUITES) {
			vectors.add(vector("cipher-suite", "rfc5246-cipher-suite-" + hexName(cipherSuite), "RFC 5246 A.5",
					"TLS 1.2 ClientHello offering cipher suite 0x" + hexName(cipherSuite),
					createClientHelloWithCipherSuite(TLSVersion.TLS_1_2, cipherSuite)));
		}
		for (int cipherSuite : TLS13_CIPHER_SUITES) {
			vectors.add(vector("cipher-suite", "rfc8446-cipher-suite-" + hexName(cipherSuite), "RFC 8446 B.4",
					"TLS 1.3 ClientHello offering cipher suite 0x" + hexName(cipherSuite),
					createClientHelloWithCipherSuite(TLSVersion.TLS_1_3, cipherSuite)));
		}
	}

	private void addNamedGroupVectors(List<TLSFuzzVector> vectors) {
		for (int namedGroup : TLS13_NAMED_GROUPS) {
			vectors.add(vector("named-group", "rfc8446-named-group-" + hexName(namedGroup), "RFC 8446 B.3.1.4",
					"TLS 1.3 key_share ClientHello with named group 0x" + hexName(namedGroup),
					createClientHelloWithNamedGroup(namedGroup)));
		}
	}

	private void addSignatureSchemeVectors(List<TLSFuzzVector> vectors) {
		for (int signatureScheme : TLS_SIGNATURE_SCHEMES) {
			vectors.add(vector("signature-scheme", "rfc5246-signature-scheme-" + hexName(signatureScheme), "RFC 5246 A.4.1",
					"TLS 1.2 signature_algorithms extension value 0x" + hexName(signatureScheme),
					createClientHelloWithSignatureScheme(TLSVersion.TLS_1_2, signatureScheme)));
			vectors.add(vector("signature-scheme", "rfc8446-signature-scheme-" + hexName(signatureScheme), "RFC 8446 B.3.1.3",
					"TLS 1.3 signature_algorithms extension value 0x" + hexName(signatureScheme),
					createClientHelloWithSignatureScheme(TLSVersion.TLS_1_3, signatureScheme)));
		}
	}

	private void addExtensionTypeVectors(List<TLSFuzzVector> vectors) {
		for (int extensionType : TLS_EXTENSION_TYPES) {
			vectors.add(vector("extension-type", "rfc-extension-type-" + extensionType, "RFC 8446 B.3.1",
					"ClientHello extension type " + extensionType,
					createClientHelloWithExtension(TLSVersion.TLS_1_3, extensionType)));
		}
	}

	private void addMalformedLengthVectors(List<TLSFuzzVector> vectors) {
		vectors.add(vector("malformed-length", "malformed-record-declared-too-short", "RFC 5246 A.1 / RFC 8446 B.1",
				"TLSPlaintext length says 1 while fragment has 4 bytes",
				arrayUtils.appendAllArrays(new byte[] { 0x16, 0x03, 0x03, 0x00, 0x01 }, hex(0x01, 0x00, 0x00, 0x00))));
		vectors.add(vector("malformed-length", "malformed-record-declared-too-long", "RFC 5246 A.1 / RFC 8446 B.1",
				"TLSPlaintext length says 255 while fragment has 4 bytes",
				arrayUtils.appendAllArrays(new byte[] { 0x16, 0x03, 0x03, 0x00, (byte) 0xff },
						hex(0x01, 0x00, 0x00, 0x00))));
		vectors.add(vector("malformed-length", "malformed-handshake-declared-too-long", "RFC 5246 A.4 / RFC 8446 B.3",
				"Handshake header length says 65535 with no body", tlsPlaintext(22, 0x0303, hex(0x01, 0x00, 0xff, 0xff))));
	}

	private TLSFuzzVector vector(String category, String name, String rfc, String description, byte[] data) {
		return new TLSFuzzVector(name, category, rfc, description, data);
	}

	private byte[] tlsPlaintext(int contentType, int version, byte[] fragment) {
		return arrayUtils.appendAllArrays(new byte[] { (byte) contentType }, uint16(version), uint16(fragment.length),
				fragment);
	}

	private byte[] recordHeader(int contentType, int version, int declaredLength) {
		return arrayUtils.appendAllArrays(new byte[] { (byte) contentType }, uint16(version), uint16(declaredLength));
	}

	private byte[] handshakeRecord(int handshakeType, int version, byte[] body) {
		return tlsPlaintext(22, version, arrayUtils.appendAllArrays(new byte[] { (byte) handshakeType },
				uint24(body.length), body));
	}

	private byte[] vector8(byte[] data) {
		return arrayUtils.appendAllArrays(new byte[] { (byte) data.length }, data);
	}

	private byte[] randomVector(int size) {
		return vector8(RandomUtil.getInstance().generateRandomArray(size));
	}

	private byte[] vector16(byte[] data) {
		return arrayUtils.appendAllArrays(uint16(data.length), data);
	}

	private byte[] uint16(int value) {
		return new byte[] { (byte) ((value >>> 8) & 0xff), (byte) (value & 0xff) };
	}

	private byte[] uint24(int value) {
		return new byte[] { (byte) ((value >>> 16) & 0xff), (byte) ((value >>> 8) & 0xff), (byte) (value & 0xff) };
	}

	private String hexName(int value) {
		return String.format("%04x", value);
	}

	private byte[] hex(int... values) {
		byte[] data = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			data[i] = (byte) values[i];
		}
		return data;
	}
}
