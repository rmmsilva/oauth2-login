package com.maedare.oauth2login.config;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

public class CustomOauth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private final StringKeyGenerator stateGenerator = () -> UUID.randomUUID().toString();
	private final ClientRegistration clientRegistration;
	private final AntPathRequestMatcher authorizationRequestMatcher;

	public CustomOauth2AuthorizationRequestResolver(ClientRegistration clientRegistration,
			String authorizationRequestUri) {
		this.clientRegistration = clientRegistration;
		this.authorizationRequestMatcher = new AntPathRequestMatcher(authorizationRequestUri);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		if (!authorizationRequestMatcher.matches(request)) {
			return null;
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());

		String redirectUri = expandRedirectUri(request);

		return OAuth2AuthorizationRequest.authorizationCode()
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.additionalParameters(additionalParameters)
				.build();
	}

	private String expandRedirectUri(HttpServletRequest request) {
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());
		String baseUrl = UriComponentsBuilder
				.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.replacePath(request.getContextPath())
				.build()
				.toUriString();
		uriVariables.put("baseUrl", baseUrl);
		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
				.buildAndExpand(uriVariables)
				.toUriString();
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		return null;
	}

}
