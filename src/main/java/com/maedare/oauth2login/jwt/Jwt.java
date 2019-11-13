package com.maedare.oauth2login.jwt;

import com.nimbusds.jose.Header;
import com.nimbusds.jwt.JWTClaimsSet;

public class Jwt {

	private final Header header;

	private final JWTClaimsSet claimsSet;

	public Jwt(Header header, JWTClaimsSet claimsSet) {
		this.header = header;
		this.claimsSet = claimsSet;
	}

	public Header getHeader() {
		return header;
	}

	public JWTClaimsSet getClaimsSet() {
		return claimsSet;
	}

}
