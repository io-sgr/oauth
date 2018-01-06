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

package io.sgr.oauth.server.core.models;

import static io.sgr.oauth.core.utils.Preconditions.notEmptyString;
import static io.sgr.oauth.core.utils.Preconditions.notNull;

import io.sgr.oauth.core.v20.GrantType;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class TokenRequest {

	private final GrantType grantType;
	private final String clientId;
	private final String clientSecret;
	private final String redirectUri;
	private final String code;
	private final String refreshToken;
	private final String username;
	private final String password;
	private final List<String> scopes;

	/**
	 * @param grantType    The grant type
	 * @param clientId     The client ID
	 * @param clientSecret The client secret
	 * @param redirectUri  The redirect URI
	 * @param code         The authorization code
	 * @param refreshToken The refresh token
	 * @param username     The username
	 * @param password     The password
	 * @param scopes       The scopes
	 */
	public TokenRequest(
			final GrantType grantType, final String clientId, final String clientSecret, final String redirectUri,
			final String code,
			final String refreshToken,
			final String username, final String password, final List<String> scopes) {
		notNull(grantType, "Missing grant type");
		this.grantType = grantType;
		notEmptyString(clientId, "Missing client ID");
		this.clientId = clientId;
		notEmptyString(clientSecret, "Missing client secret");
		this.clientSecret = clientSecret;
		notEmptyString(redirectUri, "Missing redirect uri");
		try {
			this.redirectUri = URLDecoder.decode(redirectUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		this.code = code;
		this.refreshToken = refreshToken;
		this.username = username;
		this.password = password;
		this.scopes = scopes;
	}

	/**
	 * @return The grant type
	 */
	public GrantType getGrantType() {
		return grantType;
	}

	/**
	 * @return The client ID
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * @return The client secret
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	/**
	 * @return The redirect URI
	 */
	public String getRedirectUri() {
		return redirectUri;
	}

	/**
	 * @return The authorization code
	 */
	public Optional<String> getCode() {
		return Optional.ofNullable(code);
	}

	/**
	 * @return The refresh token
	 */
	public Optional<String> getRefreshToken() {
		return Optional.ofNullable(refreshToken);
	}

	/**
	 * @return The username
	 */
	public Optional<String> getUsername() {
		return Optional.ofNullable(username);
	}

	/**
	 * @return The password
	 */
	public Optional<String> getPassword() {
		return Optional.ofNullable(password);
	}

	/**
	 * @return The scopes
	 */
	public Optional<List<String>> getScopes() {
		return Optional.ofNullable(scopes == null ? null : Collections.unmodifiableList(scopes));
	}

}
