package com.maedare.oauth2login.jwt;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthentication implements Authentication {

	private static final long serialVersionUID = -8188751815982372252L;

	private final Map<String, Object> claims;

	private final Collection<? extends GrantedAuthority> authorities;

	public JwtAuthentication(Map<String, Object> claims, Collection<? extends GrantedAuthority> authorities) {
		super();
		this.claims = claims;
		this.authorities = authorities;
	}

	@Override
	public String getName() {
		return (String) claims.get("sub");
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return claims;
	}

	@Override
	public Object getPrincipal() {
		return claims.get("funcional");
	}

	@Override
	public boolean isAuthenticated() {
		return true;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		throw new IllegalArgumentException();
	}

}
