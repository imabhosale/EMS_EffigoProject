package com.ems.util;

public enum Role {
	ADMIN,
	USER;
	
	@Override
	public String toString() {
		return name();
	}
}
