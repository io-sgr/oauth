/*
 * Copyright 2017-2019 SgrAlpha
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

package io.sgr.oauth.server.authserver.core;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.ServerErrorException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.core.exceptions.UnsupportedResponseTypeException;
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
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

public class AuthorizationServer {

	private static final int DEFAULT_AUTHORIZATION_CODE_EXPIRES_TIME_AMOUNT = 1;
	private static final TemporalUnit DEFAULT_AUTHORIZATION_CODE_EXPIRES_TIME_UNIT = ChronoUnit.MINUTES;

	private final OAuthV2Service service;
	private final AuthorizationCodec<AuthorizationDetail> authCodec;

	private AuthorizationServer(final OAuthV2Service service, final AuthorizationCodec<AuthorizationDetail> authCodec) {
		notNull(service, "Missing implementation of " + OAuthV2Service.class);
		this.service = service;
		notNull(service, "Missing implementation of " + AuthorizationCodec.class);
		this.authCodec = authCodec;
	}

	/**
	 *
	 * @param service The OAuth V2 service provider
	 * @return The builder
	 */
	public static Builder with(final OAuthV2Service service) {
		return new Builder(service);
	}

	public <T> AuthorizationDetail preAuthorization(final T from, final AuthRequestParser<T> parser, final String currentUser, final Locale locale)
			throws InvalidRequestException, InvalidClientException, InvalidScopeException, UnsupportedResponseTypeException {
		notNull(from, "Cannot parse from NULL");
		notNull(parser, "Parser needs to be specified");
		notEmptyString(currentUser, "Current user needs to be specified");
		final AuthorizationRequest authReq = parser.parse(from);
		final ResponseType responseType = authReq.getResponseType();
		final String clientId = authReq.getClientId();
		final String redirectUri = authReq.getRedirectUri();
		final List<String> requestedScopes = authReq.getScopes();
		final String state = authReq.getState().orElse(null);
		final Optional<OAuthClientInfo> clientInfo = getOAuthV2Service().getOAuthClientById(clientId);
		if (!clientInfo.isPresent()) {
			throw new InvalidClientException("Unauthorized client");
		}
		final List<String> callbacks = clientInfo.map(OAuthClientInfo::getCallbacks).orElse(null);
		if (!OAuthServerUtil.isRedirectUriRegistered(redirectUri, callbacks)) {
			throw new InvalidRequestException(MessageFormat.format("Redirect URI mismatch: {0}", redirectUri));
		}
		final List<ScopeDefinition> checkedScopes = new LinkedList<>();
		for (String id : requestedScopes) {
			if (isEmptyString(id)) {
				continue;
			}
			Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeById(id, locale);
			if (!scope.isPresent()) {
				throw new InvalidScopeException(MessageFormat.format("Invalid scope: {0}", id));
			}
			checkedScopes.add(scope.get());
		}
		switch (responseType) {
			case CODE:
				final boolean isAuthorized = getOAuthV2Service().checkIfUserAuthorized(currentUser, clientId, requestedScopes);
				return new AuthorizationDetail(responseType, clientInfo.get(), currentUser, redirectUri, checkedScopes, state, isAuthorized);
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
			if (uriBuilder.lastIndexOf("?") != uriBuilder.length() - 1) {
				uriBuilder.append("&");
			}
			uriBuilder.append(OAuth20.OAUTH_STATE).append("=").append(state);
		}
		if (approved) {
			switch (responseType) {
				case CODE:
					final String code;
					try {
						code = authCodec.encode(authDetail);
					} catch (JwtException e) {
						throw new ServerErrorException("Failed to generate authorization code");
					}
					if (uriBuilder.indexOf("?") < 0) {
						uriBuilder.append("?");
					}
					if (uriBuilder.lastIndexOf("?") != uriBuilder.length() - 1) {
						uriBuilder.append("&");
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
				if (uriBuilder.lastIndexOf("?") != uriBuilder.length() - 1) {
					uriBuilder.append("&");
				}
				uriBuilder
						.append(OAuth20.OAUTH_ERROR).append("=").append("access_denied")
						.append("&")
						.append(OAuth20.OAUTH_ERROR_DESCRIPTION).append("=").append(URLEncoder.encode("User denied the request", "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
		}
		return uriBuilder.toString();
	}

	/**
	 * @param from   The source to parse and generate/refresh token from
	 * @param parser The parser to parse source to TokenRequest
	 * @param <T>    The type of source to parse from
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
	 * @throws ServerErrorException          If something is wrong when generating/refreshing access token
	 */
	public <T> OAuthCredential generateToken(final T from, final TokenRequestParser<T> parser)
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
				if (!getOAuthV2Service().isValidRefreshToken(clientId, refreshToken)) {
					throw new InvalidGrantException("Invalid refresh token");
				}
				credential = getOAuthV2Service().refreshAccessToken(clientId, refreshToken);
				break;
			case AUTHORIZATION_CODE:
				final String authCode = tokenReq.getCode().orElseThrow(() -> new InvalidRequestException("Missing authorization code"));
				if (getOAuthV2Service().isAuthorizationCodeRevoked(authCode)) {
					throw new InvalidGrantException("Authorization code already been revoked");
				}
				final AuthorizationDetail authDetail;
				try {
					authDetail = authCodec.decode(authCode);
				} catch (ExpiredJwtException e) {
					throw new InvalidGrantException("Expired authorization code");
				} catch (JwtException e) {
					throw new InvalidGrantException("Unable to parse authorization code");
				} finally {
					getOAuthV2Service().revokeAuthorizationCode(authCode);
				}
				if (authDetail == null) {
					throw new InvalidGrantException("Invalid authorization code");
				}
				if (!redirectUri.equals(authDetail.getRedirectUri())) {
					throw new InvalidGrantException(MessageFormat.format("Redirect URI mismatch: {0}", redirectUri));
				}
				userId = authDetail.getCurrentUser();
				scopes = new HashSet<>(getOAuthV2Service().getGrantedScopes(clientId, userId));
				scopes.addAll(authDetail.getScopes().parallelStream().map(ScopeDefinition::getId).collect(Collectors.toList()));
				credential = getOAuthV2Service().generateAccessToken(clientId, userId, scopes);
				break;
			case PASSWORD:
				final List<String> scopeIdList = tokenReq.getScopes().orElse(Collections.emptyList());
				if (scopeIdList.isEmpty()) {
					throw new InvalidRequestException("Missing scope");
				}
				final List<String> checkedScopes = new LinkedList<>();
				for (String id : scopeIdList) {
					if (isEmptyString(id)) {
						continue;
					}
					Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeById(id, null);
					if (!scope.isPresent()) {
						throw new InvalidScopeException(MessageFormat.format("Unknown scope: {0}", id));
					}
					checkedScopes.add(scope.get().getId());
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
		if (credential == null) {
			throw new ServerErrorException("Unable to generate access token");
		}
		return credential;
	}

	private OAuthV2Service getOAuthV2Service() {
		return service;
	}

	public static class Builder {

		private OAuthV2Service service;

		private String issuer;
		private String serverSecret;
		private Long authCodeExpiresTimeAmount;
		private TemporalUnit authCodeExpiresTimeUnit;

		private Builder(final OAuthV2Service service) {
			notNull(service, "Missing implementation of " + OAuthV2Service.class);
			this.service = service;
		}

		/**
		 *
		 * @return The OAuth V2 service provider
		 */
		public OAuthV2Service getOAuthV2Service() {
			return service;
		}

		/**
		 *
		 * @return The issuer
		 */
		public String getIssuer() {
			return issuer;
		}

		/**
		 *
		 * @param issuer The issuer
		 * @return The builder
		 */
		public Builder setIssuer(final String issuer) {
			notEmptyString(issuer, "Issuer needs to be specified");
			this.issuer = issuer;
			return this;
		}

		/**
		 *
		 * @return The server secret
		 */
		public String getServerSecret() {
			return serverSecret;
		}

		/**
		 *
		 * @param serverSecret The server secret
		 * @return The builder
		 */
		public Builder setServerSecret(final String serverSecret) {
			notEmptyString(serverSecret, "Server secret needs to be specified");
			this.serverSecret = serverSecret;
			return this;
		}

		/**
		 *
		 * @return The amount of authorization code expire time
		 */
		public Long getAuthCodeExpiresTimeAmount() {
			return authCodeExpiresTimeAmount;
		}

		/**
		 *
		 * @return The unit of authorization code expire time
		 */
		public TemporalUnit getAuthCodeExpiresTimeUnit() {
			return authCodeExpiresTimeUnit;
		}

		/**
		 * @param amount The time period that authorization code can live.
		 * @param unit   The unit of time amount, default to minute.
		 * @return The builder
		 */
		public Builder setAuthCodeExpiresAfter(final Long amount, final TemporalUnit unit) {
			this.authCodeExpiresTimeAmount = amount;
			this.authCodeExpiresTimeUnit = unit;
			return this;
		}

		/**
		 * @return The authorization server which built with specified parameters.
		 */
		public AuthorizationServer build() {
			final JwtAuthorizationCodec authCodec = new JwtAuthorizationCodec(issuer, serverSecret)
					.setExpiresIn(authCodeExpiresTimeAmount == null || authCodeExpiresTimeAmount <=0 ? DEFAULT_AUTHORIZATION_CODE_EXPIRES_TIME_AMOUNT : authCodeExpiresTimeAmount,
							authCodeExpiresTimeUnit == null ? DEFAULT_AUTHORIZATION_CODE_EXPIRES_TIME_UNIT : authCodeExpiresTimeUnit);
			return new AuthorizationServer(this.service, authCodec);
		}

	}

}
