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

import io.sgr.oauth.core.v20.ResponseType;
import io.sgr.oauth.server.core.models.OAuthClientInfo;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class AuthorizationDetail implements Serializable {

	private final ResponseType responseType;
	private final OAuthClientInfo client;
	private final String currentUser;
	private final List<String> scopes;
	private final String redirectUri;
	private final String state;

	/**
	 * @param responseType The response type
	 * @param client       The client
	 * @param currentUser  Current user
	 * @param redirectUri  The redirect URI
	 * @param scopes       The scopes
	 * @param state        The state
	 */
	public AuthorizationDetail(
			final ResponseType responseType, final OAuthClientInfo client, final String currentUser, final String redirectUri, final List<String> scopes,
			final String state) {
		notNull(responseType, "Missing response type");
		this.responseType = responseType;
		notNull(client, "Missing client info");
		this.client = client;
		notEmptyString(currentUser, "Missing current user");
		this.currentUser = currentUser;
		notEmptyString(redirectUri, "Missing redirect URI");
		try {
			this.redirectUri = URLDecoder.decode(redirectUri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		notNull(scopes, "Missing scopes");
		if (scopes.isEmpty()) {
			throw new IllegalArgumentException("Missing scopes");
		}
		this.scopes = scopes;
		this.state = isEmptyString(state) ? null : state;
	}

	/**
	 * @return The response type
	 */
	public ResponseType getResponseType() {
		return responseType;
	}

	/**
	 * @return The client ID
	 */
	public OAuthClientInfo getClient() {
		return client;
	}

	/**
	 * @return The current user
	 */
	public String getCurrentUser() {
		return currentUser;
	}

	/**
	 * @return The redirect URI
	 */
	public String getRedirectUri() {
		return redirectUri;
	}

	/**
	 * @return The scopes
	 */
	public List<String> getScopes() {
		return Collections.unmodifiableList(scopes);
	}

	/**
	 * @return The state
	 */
	public Optional<String> getState() {
		return Optional.ofNullable(state);
	}
}
