package com.rakkau.connectors;

import org.identityconnectors.common.StringUtil;

public class SuccessFactorsFilter {
	public String byName;
	public String byUid;
	public String byEmailAddress;

	public boolean isEmpty() {
		return StringUtil.isBlank(byName) && StringUtil.isBlank(byUid) && StringUtil.isBlank(byEmailAddress);
	}

	public boolean isNotEmpty() {
		return !this.isEmpty();
	}

	@Override
	public String toString() {
		return "SuccessFactorsFilter{" +
				"byName='" + byName + '\'' +
				", byUid=" + byUid +
				", byEmailAddress='" + byEmailAddress + '\'' +
				'}';
	}
}
