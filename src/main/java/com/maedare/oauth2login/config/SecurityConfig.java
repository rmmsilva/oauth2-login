package com.maedare.oauth2login.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.maedare.oauth2login.jwt.JwtParser;
import com.maedare.oauth2login.jwt.TokenValidator;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final String LOGIN_ENTRYPOINT = "/login";

	private final String REGISTRATION_ID = "sts";

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
				.anyRequest()
				.authenticated()
			.and()
			.exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_ENTRYPOINT))
			;
		// @formatter:on

		http.addFilterAfter(redirectFilter(), LogoutFilter.class);
		http.addFilterAfter(authFilter(), AbstractPreAuthenticatedProcessingFilter.class);
	}

	private ClientRegistration clientRegistration() {
		return clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
	}

	private CustomOauth2AuthorizationRequestResolver requestResolver() {
		return new CustomOauth2AuthorizationRequestResolver(clientRegistration(), LOGIN_ENTRYPOINT);
	}

	private OAuth2AuthorizationRequestRedirectFilter redirectFilter() {
		return new OAuth2AuthorizationRequestRedirectFilter(requestResolver());
	}

	private OpenIdAuthenticationProvider authProvider() {
		return new OpenIdAuthenticationProvider(new DefaultAuthorizationCodeTokenResponseClient(),
				new JwtParser(),
				new TokenValidator());
	}

	private OpenIdAuthenticationFilter authFilter() {
		return new OpenIdAuthenticationFilter(clientRegistration(),
				new HttpSessionOAuth2AuthorizationRequestRepository(),
				authProvider(),
				"/oauth2/callback/sts");
	}
}
