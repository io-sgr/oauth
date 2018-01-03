/*
 * Copyright 2018 SgrAlpha
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

package io.sgr.oauth.server;

import static io.sgr.oauth.core.utils.Preconditions.isEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.OAuthCredential;
import io.sgr.oauth.core.v20.GrantType;
import io.sgr.oauth.server.core.OAuthV2Service;
import io.sgr.oauth.core.exceptions.InvalidClientException;
import io.sgr.oauth.core.exceptions.InvalidGrantException;
import io.sgr.oauth.core.exceptions.InvalidRequestException;
import io.sgr.oauth.core.exceptions.InvalidScopeException;
import io.sgr.oauth.core.exceptions.UnsupportedGrantTypeException;
import io.sgr.oauth.server.core.models.AccessDefinition;
import io.sgr.oauth.server.core.models.OAuthClientInfo;
import io.sgr.oauth.server.core.models.ScopeDefinition;
import io.sgr.oauth.server.core.models.TokenRequest;
import io.sgr.oauth.server.core.utils.OAuthServerUtil;
import io.sgr.oauth.server.core.TokenRequestParser;

import java.text.MessageFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class AuthorizationServer {

	private final OAuthV2Service service;

	private AuthorizationServer(final OAuthV2Service service) {
		notNull(service, "Missing implementation of " + OAuthV2Service.class);
		this.service = service;
	}

	public static Builder with(final OAuthV2Service service) {
		return new Builder(service);
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
	 */
	public <T> Optional<OAuthCredential> generateToken(final T from, final TokenRequestParser<T> parser)
			throws InvalidRequestException, InvalidClientException, InvalidGrantException, InvalidScopeException, UnsupportedGrantTypeException {
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
				final String authCode = tokenReq.getCode().orElseThrow(() -> new InvalidRequestException("Missing authorization code"));
				final AccessDefinition accessDef = getOAuthV2Service().getOAuthAccessDefinitionByAuthCode(authCode);
				if (accessDef == null) {
					throw new InvalidGrantException("Unknown code");
				}
				getOAuthV2Service().revokeAuthorizationCode(authCode);
				if (!redirectUri.equals(accessDef.getRedirectUri())) {
					throw new InvalidGrantException(MessageFormat.format("Redirect URI mismatch: {0}", redirectUri));
				}
				userId = accessDef.getUserId();
				scopes = new HashSet<>(getOAuthV2Service().getGrantedScopes(clientId, userId));
				scopes.addAll(accessDef.getScopes());
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
					Optional<ScopeDefinition> scope = getOAuthV2Service().getScopeByName(name);
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

	private OAuthV2Service getOAuthV2Service() {
		return service;
	}

	public static class Builder {

		private OAuthV2Service service;

		private Builder(final OAuthV2Service service) {
			notNull(service, "Missing implementation of " + OAuthV2Service.class);
			this.service = service;
		}

		public AuthorizationServer build() {
			return new AuthorizationServer(this.service);
		}

	}

}
