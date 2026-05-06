package tech.cybersword.tls.fuzzer.generator;

import java.util.Arrays;

public class TLSFuzzVector {

	private final String name;
	private final String category;
	private final String rfc;
	private final String description;
	private final byte[] data;

	public TLSFuzzVector(String name, String rfc, String description, byte[] data) {
		this(name, "general", rfc, description, data);
	}

	public TLSFuzzVector(String name, String category, String rfc, String description, byte[] data) {
		this.name = name;
		this.category = category;
		this.rfc = rfc;
		this.description = description;
		this.data = data.clone();
	}

	public String getName() {
		return name;
	}

	public String getCategory() {
		return category;
	}

	public String getRfc() {
		return rfc;
	}

	public String getDescription() {
		return description;
	}

	public byte[] getData() {
		return data.clone();
	}

	public int size() {
		return data.length;
	}

	@Override
	public String toString() {
		return "TLSFuzzVector{name='" + name + "', category='" + category + "', rfc='" + rfc + "', size="
				+ data.length + "}";
	}

	@Override
	public int hashCode() {
		int result = name.hashCode();
		result = 31 * result + category.hashCode();
		result = 31 * result + rfc.hashCode();
		result = 31 * result + Arrays.hashCode(data);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TLSFuzzVector other)) {
			return false;
		}
		return name.equals(other.name) && category.equals(other.category) && rfc.equals(other.rfc)
				&& Arrays.equals(data, other.data);
	}
}
