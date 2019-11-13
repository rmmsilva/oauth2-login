package com.maedare.oauth2login.jwt;

import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@Component
public class JwtParser {

	public Jwt parse(String token) {
		try {
			JWT jwt = JWTParser.parse(token);

			return new Jwt(jwt.getHeader(), jwt.getJWTClaimsSet());
		} catch (Exception ex) {
			throw new JwtException(String.format("Erro! Não foi possível converter jwt", ex.getMessage()), ex);
		}
	}

}
