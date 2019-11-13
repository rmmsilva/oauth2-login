package com.maedare.oauth2login.config;

import static java.util.Arrays.asList;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;

import com.maedare.oauth2login.jwt.Jwt;
import com.maedare.oauth2login.jwt.JwtAuthentication;
import com.maedare.oauth2login.jwt.JwtParser;
import com.maedare.oauth2login.jwt.TokenValidator;

public class OpenIdAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private final JwtParser jwtParser;

	private final TokenValidator tokenValidator;

	public OpenIdAuthenticationProvider(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
			JwtParser jwtParser,
			TokenValidator tokenValidator) {
		this.accessTokenResponseClient = accessTokenResponseClient;
		this.jwtParser = jwtParser;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken) authentication;

		OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication
				.getAuthorizationExchange().getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication
				.getAuthorizationExchange().getAuthorizationResponse();

		if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
			OAuth2Error oauth2Error = new OAuth2Error("Erro! Requisição inválida");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		OAuth2AccessTokenResponse accessTokenResponse;
		try {
			accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(
					new OAuth2AuthorizationCodeGrantRequest(
							authorizationCodeAuthentication.getClientRegistration(),
							authorizationCodeAuthentication.getAuthorizationExchange()));
		} catch (OAuth2AuthorizationException ex) {
			OAuth2Error oauth2Error = ex.getError();
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		String idTokenStr = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);
		Jwt idToken = jwtParser.parse(idTokenStr);

		tokenValidator.validate(idToken);

		Jwt accessToken = jwtParser.parse(accessTokenResponse.getAccessToken().getTokenValue());

		Map<String, Object> claims = new HashMap<>(idToken.getClaimsSet().getClaims());
		claims.put("funcional", accessToken.getClaimsSet().getClaim("sub"));

		return new JwtAuthentication(claims, asList(new SimpleGrantedAuthority("ROLE_CONTINGENCIA")));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
