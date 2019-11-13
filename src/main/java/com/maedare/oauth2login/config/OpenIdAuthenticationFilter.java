package com.maedare.oauth2login.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class OpenIdAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private final ClientRegistration clientRegistration;

	private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	private final OpenIdAuthenticationProvider authenticationProvider;

	public OpenIdAuthenticationFilter(
			ClientRegistration clientRegistration,
			AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
			OpenIdAuthenticationProvider authenticationProvider,
			String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
		this.clientRegistration = clientRegistration;
		this.authorizationRequestRepository = authorizationRequestRepository;
		this.authenticationProvider = authenticationProvider;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
				.removeAuthorizationRequest(request, response);

		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error("Erro! Requisição não encontrada");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		String redirectUri = UriComponentsBuilder
				.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.build()
				.toUriString();

		String code = request.getParameter(OAuth2ParameterNames.CODE);
		String state = request.getParameter(OAuth2ParameterNames.STATE);

		if (StringUtils.isEmpty(code) || StringUtils.isEmpty(state)) {
			OAuth2Error oauth2Error = new OAuth2Error("Erro! Requisição inválida");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();

		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(
				clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));

		return authenticationProvider.authenticate(authenticationRequest);
	}

}
