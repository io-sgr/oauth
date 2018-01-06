/*
 * Copyright 2017-2018 SgrAlpha
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package io.sgr.oauth.authserver.core;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
import io.sgr.oauth.core.utils.JsonUtil;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.core.v20.OAuth20;
import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.AuthRequestParser;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.server.core.TokenRequestParser;
import io.sgr.oauth.server.core.models.AuthorizationRequest;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import io.sgr.oauth.server.core.models.TokenRequest;
import io.sgr.oauth.server.core.utils.OAuthServerUtil;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class AuthorizationServer {

	private static final int DEFAULT_AUTHORIZATION_CODE_EXPIRES_IN_MINUTES = 1;

	private final OAuthV2Service service;
	private long authCodeExpiresTimeAmount;
	private TemporalUnit authCodeExpiresTimeUnit;

	private AuthorizationServer(final OAuthV2Service service,
	                            final long authCodeExpiresTimeAmount, final TemporalUnit authCodeExpiresTimeUnit) {
		notNull(service, "Missing implementation of " + OAuthV2Service.class);
		this.service = service;
		if (authCodeExpiresTimeAmount <= 0) {
			throw new IllegalArgumentException(MessageFormat.format("Authorization token expiration should be greater than 0, but got {0}", authCodeExpiresTimeAmount));
		}
		this.authCodeExpiresTimeAmount = authCodeExpiresTimeAmount;
		notNull(authCodeExpiresTimeUnit, "Time unit needs to be specified");
	}

	public static Builder with(final OAuthV2Service service) {
		return new Builder(service);
	}

	public <T> AuthorizationDetail preAuthorization(final String currentUser, final T from, final AuthRequestParser<T> parser)
			throws InvalidRequestException, InvalidClientException, InvalidScopeException, UnsupportedResponseTypeException {
		notEmptyString(currentUser, "Current user needs to be specified");
		notNull(from, "Cannot parse from NULL");
		notNull(parser, "Parser needs to be specified");
		final AuthorizationRequest authReq = parser.parse(from);
		final ResponseType responseType = authReq.getResponseType();
		final String clientId = authReq.getClientId();
		final String redirectUri = authReq.getRedirectUri();
		final List<String> requestedScopes = authReq.getScopes();
		final String state = authReq.getState().orElse(null);
		final Optional<OAuthClientInfo> clientInfo = getOAuthV2Service().getOAuthClientById(clientId);
		if (!clientInfo.isPresent()) {
			throw new InvalidClientException("Unauthorized client ID or secret");
		}
		final List<String> callbacks = clientInfo.map(OAuthClientInfo::getCallbacks).orElse(null);
		if (!OAuthServerUtil.isRedirectUriRegistered(redirectUri, callbacks)) {
			throw new InvalidRequestException(MessageFormat.format("Redirect URI mismatch: {0}", redirectUri));
		}
		final List<String> checkedScopes = new LinkedList<>();
		for (String id : requestedScopes) {
			if (isEmptyString(id)) {
				continue;
			}
			Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeById(id);
			if (!scope.isPresent()) {
				throw new InvalidScopeException(MessageFormat.format("Invalid scope: {0}", id));
			}
			checkedScopes.add(scope.get().getId());
		}
		switch (responseType) {
			case CODE:
				return new AuthorizationDetail(responseType, clientInfo.get(), currentUser, redirectUri, checkedScopes, state);
			default:
				throw new UnsupportedResponseTypeException(MessageFormat.format("Unsupported response type: {0}", responseType));
		}
	}

	public String postAuthorization(final boolean approved, final AuthorizationDetail authDetail)
			throws UnsupportedResponseTypeException, ServerErrorException {
		final ResponseType responseType = authDetail.getResponseType();
		final String redirectUri = authDetail.getRedirectUri();
		final String state = authDetail.getState().orElse(null);

		final StringBuilder uriBuilder = new StringBuilder(redirectUri);
		if (!isEmptyString(state)) {
			if (uriBuilder.indexOf("?") < 0) {
				uriBuilder.append("?");
			}
			uriBuilder.append(OAuth20.OAUTH_STATE).append("=").append(state);
		}
		if (approved) {
			switch (responseType) {
				case CODE:
					final String serverTokenIssuer = getOAuthV2Service().getServerTokenIssuer();
					if (isEmptyString(serverTokenIssuer)) {
						throw new ServerErrorException("Unable to generate authorization token because of missing server token issuer");
					}
					final String serverTokenSecret = getOAuthV2Service().getServerTokenSecret();
					if (isEmptyString(serverTokenSecret)) {
						throw new ServerErrorException("Unable to generate authorization token because of missing server token secret");
					}
					final String code = encode(serverTokenIssuer, serverTokenSecret, authDetail);
					getOAuthV2Service().cacheAuthorizationCode(code);
					if (uriBuilder.indexOf("?") < 0) {
						uriBuilder.append("?");
					}
					uriBuilder.append(OAuth20.OAUTH_CODE).append("=").append(code);
					break;
				default:
					throw new UnsupportedResponseTypeException(MessageFormat.format("Unsupported response type: {0}", responseType));
			}
		} else {
			try {
				if (uriBuilder.indexOf("?") < 0) {
					uriBuilder.append("?");
				}
				uriBuilder
						.append(OAuth20.OAUTH_ERROR).append("=").append("access_denied")
						.append(OAuth20.OAUTH_ERROR_DESCRIPTION).append("=").append(URLEncoder.encode("User denied the request", "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
		}
		return uriBuilder.toString();
	}

	/**
	 * @param from   The source to parse and generate/refresh token from
	 * @param parser THe parser to parse source to TokenRequest
	 * @return The generated/refreshed OAuth access token
	 * @throws InvalidRequestException       The request is missing a parameter so the server can’t proceed with the request.
	 *                                       This may also be returned if the request includes an unsupported parameter
	 *                                       or repeats a parameter.
	 * @throws InvalidClientException        Client authentication failed, such as if the request contains an invalid client ID or secret.
	 *                                       Send an HTTP 401 response in this case.
	 * @throws InvalidGrantException         The authorization code (or user’s password for the password grant type) is invalid or expired.
	 *                                       This is also the error you would return if the redirect URL given in the authorization
	 *                                       grant does not match the URL provided in this access token request.
	 * @throws InvalidScopeException         For access token requests that include a scope (password or client_credentials grants),
	 *                                       this error indicates an invalid scope value in the request.
	 * @throws UnsupportedGrantTypeException If a grant type is requested that the authorization server doesn't recognize, use this code.
	 *                                       Note that unknown grant types also use this specific error code rather than
	 *                                       using the invalid_request above.
	 * @throws ServerErrorException
	 */
	public <T> Optional<OAuthCredential> generateToken(final T from, final TokenRequestParser<T> parser)
			throws InvalidRequestException, InvalidClientException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException, ServerErrorException {
		notNull(from, "Cannot parse from NULL");
		notNull(parser, "Parser needs to be specified");
		final TokenRequest tokenReq = parser.parse(from);
		final String clientId = tokenReq.getClientId();
		final String clientSecret = tokenReq.getClientSecret();
		final String redirectUri = tokenReq.getRedirectUri();
		final GrantType grantType = tokenReq.getGrantType();
		final Optional<OAuthClientInfo> clientInfo = getOAuthV2Service().getOAuthClientByIdAndSecret(clientId, clientSecret);
		if (!clientInfo.isPresent()) {
			throw new InvalidClientException("Unauthorized client ID or secret");
		}
		final List<String> callbacks = clientInfo.map(OAuthClientInfo::getCallbacks).orElse(null);
		if (!OAuthServerUtil.isRedirectUriRegistered(redirectUri, callbacks)) {
			throw new InvalidGrantException(MessageFormat.format("Unknown redirect URI: {0}", redirectUri));
		}

		final String userId;
		final Collection<String> scopes;
		final OAuthCredential credential;
		switch (grantType) {
			case REFRESH_TOKEN:
				final String refreshToken = tokenReq.getRefreshToken().orElseThrow(() -> new InvalidRequestException("Missing refresh token"));
				credential = getOAuthV2Service().refreshAccessToken(clientId, refreshToken);
				break;
			case AUTHORIZATION_CODE:
				final String serverTokenIssuer = getOAuthV2Service().getServerTokenIssuer();
				if (isEmptyString(serverTokenIssuer)) {
					throw new ServerErrorException("Unable to parse authorization code because of missing server token issuer");
				}
				final String serverTokenSecret = getOAuthV2Service().getServerTokenSecret();
				if (isEmptyString(serverTokenSecret)) {
					throw new ServerErrorException("Unable to parse authorization code because of missing server token secret");
				}
				final String authCode = tokenReq.getCode().orElseThrow(() -> new InvalidRequestException("Missing authorization code"));
				final AuthorizationDetail authDetail = decode(serverTokenIssuer, serverTokenSecret, authCode).orElse(null);
				getOAuthV2Service().revokeAuthorizationCode(authCode);
				if (authDetail == null) {
					throw new InvalidGrantException("Invalid authorization code");
				}
				if (!redirectUri.equals(authDetail.getRedirectUri())) {
					throw new InvalidGrantException(MessageFormat.format("Redirect URI mismatch: {0}", redirectUri));
				}
				userId = authDetail.getCurrentUser();
				scopes = new HashSet<>(getOAuthV2Service().getGrantedScopes(clientId, userId));
				scopes.addAll(authDetail.getScopes());
				credential = getOAuthV2Service().generateAccessToken(clientId, userId, scopes);
				break;
			case PASSWORD:
				final List<String> names = tokenReq.getScopes().orElse(Collections.emptyList());
				if (names.isEmpty()) {
					throw new InvalidRequestException("Missing scope");
				}
				final List<String> checkedScopes = new LinkedList<>();
				for (String name : names) {
					if (isEmptyString(name)) {
						continue;
					}
					Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeById(name);
					if (!scope.isPresent()) {
						throw new InvalidScopeException(MessageFormat.format("Unknown scope: {0}", name));
					}
					checkedScopes.add(scope.get().getName());
				}
				final String username = tokenReq.getUsername().orElseThrow(() -> new InvalidRequestException("Missing username"));
				final String password = tokenReq.getPassword().orElseThrow(() -> new InvalidRequestException("Missing password"));
				userId = getOAuthV2Service().getUserIdByUsernameAndPassword(username, password);
				if (isEmptyString(userId)) {
					throw new InvalidGrantException("Unknown username or password");
				}
				scopes = new HashSet<>(getOAuthV2Service().getGrantedScopes(clientId, userId));
				scopes.addAll(checkedScopes);
				credential = getOAuthV2Service().generateAccessToken(clientId, userId, scopes);
				break;
			default:
				throw new UnsupportedGrantTypeException(MessageFormat.format("Unsupported grant type '{0}'", grantType));
		}
		return Optional.ofNullable(credential);
	}

	private String encode(final String serverTokenIssuer, final String serverTokenSecret, final AuthorizationDetail authDetail) throws ServerErrorException {
		notEmptyString(serverTokenIssuer, "Missing server token issuer");
		notEmptyString(serverTokenSecret, "Missing server token secret");
		notNull(authDetail, "Missing authorization detail");
		final Instant now = Instant.now(Clock.systemUTC());
		final Instant expiration = now.plus(authCodeExpiresTimeAmount, authCodeExpiresTimeUnit);
		try {
			return Jwts.builder()
					.setIssuer(serverTokenIssuer)
					.setSubject(JsonUtil.getObjectMapper().writeValueAsString(authDetail))
					.setIssuedAt(Date.from(now))
					.setExpiration(Date.from(expiration))
					.signWith(SignatureAlgorithm.HS512, serverTokenSecret)
					.compact();
		} catch (Exception e) {
			throw new ServerErrorException(MessageFormat.format("Unable to generate authorization token because of: {0}", e.getMessage()));
		}
	}

	private Optional<AuthorizationDetail> decode(final String serverTokenIssuer, final String serverTokenSecret, final String authCode) {
		notEmptyString(serverTokenIssuer, "Missing server token issuer");
		notEmptyString(serverTokenSecret, "Missing server token secret");
		notEmptyString(authCode, "Missing authorization code");
		try {
			final Claims body = Jwts.parser()
					.requireIssuer(serverTokenIssuer)
					.setSigningKey(serverTokenSecret)
					.parseClaimsJws(authCode).getBody();
			final String subject = body.getSubject();
			if (isEmptyString(subject)) {
				return Optional.empty();
			}
			final AuthorizationDetail authDetail = JsonUtil.getObjectMapper().readValue(subject, AuthorizationDetail.class);
			return Optional.ofNullable(authDetail);
		} catch (Exception e) {
			// Ignored
		}
		return Optional.empty();
	}

	private OAuthV2Service getOAuthV2Service() {
		return service;
	}

	public static class Builder {

		private OAuthV2Service service;

		private long authCodeExpiresTimeAmount;
		private TemporalUnit authCodeExpiresTimeUnit;

		private Builder(final OAuthV2Service service) {
			notNull(service, "Missing implementation of " + OAuthV2Service.class);
			this.service = service;
		}

		/**
		 * @param amount The time period that authorization code can live.
		 * @param unit The unit of time amount, default to minute.
		 * @return The builder
		 */
		public Builder setAuthCodeExpiresAfter(final long amount, final TemporalUnit unit) {
			this.authCodeExpiresTimeAmount = amount <= 0 ? DEFAULT_AUTHORIZATION_CODE_EXPIRES_IN_MINUTES : amount;
			this.authCodeExpiresTimeUnit = unit == null ? ChronoUnit.MINUTES : unit;
			return this;
		}

		/**
		 * @return The authorization server which built with specified parameters.
		 */
		public AuthorizationServer build() {
			return new AuthorizationServer(this.service, authCodeExpiresTimeAmount, authCodeExpiresTimeUnit);
		}

	}

}
