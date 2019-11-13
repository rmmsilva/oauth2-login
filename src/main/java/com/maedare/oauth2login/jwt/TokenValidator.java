package com.maedare.oauth2login.jwt;

import java.util.Date;
import java.util.List;

import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.CollectionUtils;

import com.nimbusds.jwt.JWTClaimsSet;

public class TokenValidator {

	public void validate(Jwt token) {
		JWTClaimsSet claims = token.getClaimsSet();
		String issuer = claims.getIssuer();
		if (issuer == null) {
			throwInvalidTokenException();
		}

		String subject = claims.getSubject();
		if (subject == null) {
			throwInvalidTokenException();
		}

		List<String> audience = claims.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			throwInvalidTokenException();
		}

		Date expiresAt = claims.getExpirationTime();
		if (expiresAt == null || new Date().after(expiresAt)) {
			throwInvalidTokenException();
		}

		Date issuedAt = claims.getIssueTime();
		if (issuedAt == null) {
			throwInvalidTokenException();
		}
	}

	private void throwInvalidTokenException() {
		throw new JwtException("Token inválido");
	}
}
